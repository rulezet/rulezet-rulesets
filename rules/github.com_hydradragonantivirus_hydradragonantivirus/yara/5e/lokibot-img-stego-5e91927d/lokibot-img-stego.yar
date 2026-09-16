rule lokibot_img_stego {
  meta:
    author      = "jeFF0Falltrades"
    description = "This rule identifies a specific variant of LokiBot which uses image steganography to obscure an encrypted payload; See reference."
    reference   = "https://blog.trendmicro.com/trendlabs-security-intelligence/lokibot-gains-new-persistence-mechanism-uses-steganography-to-hide-its-tracks/"

  strings:
    $img_gif         = "GIF8"
    $img_jpeg_1      = { FF D8 FF DB }      $img_jpeg_2      = { FF D8 FF E0 }
    $img_jpeg_3      = { FF D8 FF EE }
    $img_jpeg_4      = { FF D8 FF E1 }
    $img_png         = { 89 50 4E 47 0D 0A 1A 0A }
    $loki_enc_header = "#$%^&*()__#@$#57$#!@"

  condition:
    (for any of ($img*): ($ at 0)) and $loki_enc_header
}