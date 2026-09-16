rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_5576 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash3       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "\"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"SGs\";})(),(funct" ascii
    $s2 = "on f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s3 = "return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})()" ascii
    $s4 = "n\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function " ascii
    $s5 = "l\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}