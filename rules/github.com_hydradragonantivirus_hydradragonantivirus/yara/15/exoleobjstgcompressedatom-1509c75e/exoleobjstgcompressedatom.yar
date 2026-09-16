rule ExOleObjStgCompressedAtom {
  meta:
    author = "@tylabs"
    date   = "2015 06 09"
    ref    = "http://www.threatgeek.com/2015/06/fidelis-threat-advisory-1017-phishing-in-plain-sight.html"
    hashes = "2303c3ad273d518cbf11824ec5d2a88e"

  strings:
    $head    = { 10 00 11 10 }
    $magic   = { D0 CF 11 E0 }
    $openxml = "Package0" wide

  condition:
    ($magic at 0) and $head and $openxml
}