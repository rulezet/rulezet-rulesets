rule sig_20160519_38e352c611b3b3ddd99cdd04e8130024 {
  meta:
    description = "datamaliciousorder - file 20160519_38e352c611b3b3ddd99cdd04e8130024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc4c650e72efb8d2fef735e89e2836e17ce21187ab7c84ea38e1f029f55fa966"

  strings:
    $s1  = "var oldtime = [cognac, husbandman,leakage,  \"\"+\".\"+(\"decrease\",\"loquacious\",\"elliott\",\"malay\",\"lucerne\",\"smithson" ascii
    $s2  = "        vitriol[(harmony + \"o\"+(\"shadow\",\"carefully\",\"wrest\",\"tropics\",\"presentday\",\"chops\",\"pokemon\",\"dimensio" ascii
    $s3  = "sought = sought+ oldtime.shift();" fullword ascii
    $s4  = "weasel = ((\"firstly\", \"prodigal\", \"membership\", \"plans\", \"EjklatOeGSf\") + \"VHbDBdnUMGX\").split2();" fullword ascii
    $s5  = "superfluity = ((\"neuralgia\", \"lawyers\", \"totem\", \"banner\", \"rejoinder\", \"redundant\", \"sBtsNtyQcMgz\") + \"TaOMwH\")" ascii
    $s6  = "bestial(\"aHR0cDovLw==\".split4()+\"\\u006E\\u0065\\u0077\\u0072\\u006F\\u006D\\u006E\\u0065\\u0079\\u006F\\u006C\\u0064\\u0073" ascii
    $s7  = "harmony = ((\"surveillance\", \"formality\", \"offshore\", \"sucker\", \"pGblSsuyerH\") + \"qPMwLVJsj\").split2();" fullword ascii
    $s8  = "String.prototype.split = function () {" fullword ascii
    $s9  = "String.prototype.split2 = function () {" fullword ascii
    $s10 = "var governmental = oldtime.pop().split(\">\");" fullword ascii
    $s11 = "lackey = \"b3Blbg==\".split4();" fullword ascii
    $s12 = "String.prototype.split4 = function() {" fullword ascii
    $s13 = "            cheshire[lackey]((\"empirical\",\"silver\",\"G\" + weasel) + (\"multiplication\",\"competitive\",\"favorite\",\"indi" ascii
    $s14 = "            cheshire[lackey]((\"empirical\",\"silver\",\"G\" + weasel) + (\"multiplication\",\"competitive\",\"favorite\",\"indi" ascii
    $s15 = "  minimize = [];" fullword ascii
    $s16 = "\"turquoise\",\"assessing\",\"prostate\",\"saskatchewan\",\"tutorials\",\"08\"), superfluity)] = 0;" fullword ascii
    $s17 = "var cognac = \"QWsomebodyN0aXZsomebodylWE9iasomebodymVjdA=somebody=\".split4();" fullword ascii
    $s18 = "var economics = 3-2;  " fullword ascii
    $s19 = "action, false);" fullword ascii
    $s20 = "var humidity = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}