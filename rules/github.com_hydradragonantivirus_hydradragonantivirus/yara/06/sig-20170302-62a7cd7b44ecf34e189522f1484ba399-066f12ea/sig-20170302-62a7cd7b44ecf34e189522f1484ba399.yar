rule sig_20170302_62a7cd7b44ecf34e189522f1484ba399 {
  meta:
    description = "datamaliciousorder - file 20170302_62a7cd7b44ecf34e189522f1484ba399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0057637f7ffdae2ae9ee791283ce8565cc07b6f001e44389f8016dadd9404ae4"

  strings:
    $s1 = "var x = new Array(\"tulzaevents.com\", \"businessfilings-online-forms.com\", \"leonbacchus.com\", \"iveybusiness.vmnow.co\", \"p" ascii
    $s2 = "var x = new Array(\"tulzaevents.com\", \"businessfilings-online-forms.com\", \"leonbacchus.com\", \"iveybusiness.vmnow.co\", \"p" ascii
    $s3 = "e[raspbna2s[9-9+0]](\"G\"+\"E\"+\"T\", t4 + \":\"+ter+ter+x[i]+ter+\"c\"+\"o\"+\"u\"+\"n\"+\"ter/?\"+m,false);" fullword ascii
    $s4 = "return new ActiveXObject(g2);" fullword ascii
    $s5 = "var vDJmB = function(){" fullword ascii
    $s6 = "function mesuto() {" fullword ascii
    $s7 = "function reqty(fdga) { eval(fdga); }" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}