rule b64 {
  strings:
    $user_agent    = "SFRUUF9VU0VSX0FHRU5UCg"
    $eval          = "ZXZhbCg"
    $system        = "c3lzdGVt"
    $preg_replace  = "cHJlZ19yZXBsYWNl"
    $exec          = "ZXhlYyg"
    $base64_decode = "YmFzZTY0X2RlY29kZ"
    $perl_shebang  = "IyEvdXNyL2Jpbi9wZXJsCg"
    $cmd_exe       = "Y21kLmV4ZQ"
    $powershell    = "cG93ZXJzaGVsbC5leGU"

  condition:
    any of them
}