rule Contains_ASCII_Hex_encoded_PE_file {
  meta:
    author      = "Martin Willing (https://evild3ad.com)"
    description = "Detect an ASCII Hex encoded executable"
    reference   = "https://blogs.mcafee.com/mcafee-labs/w97m-downloader-serving-vawtrak/"
    hash        = "e56a57acf528b8cd340ae039519d5150"
    date        = "2016-03-28"

  strings:
    $MZ  = "4D5A" nocase      $DOS = "21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6f64652E" nocase      $PE  = "50450000" nocase  
  condition:
    $MZ and $DOS and $PE

}