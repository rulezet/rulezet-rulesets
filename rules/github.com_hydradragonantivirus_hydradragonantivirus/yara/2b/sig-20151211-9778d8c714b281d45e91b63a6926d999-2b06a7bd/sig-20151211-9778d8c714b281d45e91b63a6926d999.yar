rule sig_20151211_9778d8c714b281d45e91b63a6926d999 {
  meta:
    description = "datamaliciousorder - file 20151211_9778d8c714b281d45e91b63a6926d999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28fa78e84489f9593634e95f3b8cc3687a97db2504ba383eb0ad255265fee706"

  strings:
    $s1  = "function OrnwnPW(cmRPgRLZTnxpAQyfKAdHpuJVPhbAzGHqpczl) {return !isNaN(parseFloat(cmRPgRLZTnxpAQyfKAdHpuJVPhbAzGHqpczl)) && isFin" ascii
    $s2  = "function OrnwnPW(cmRPgRLZTnxpAQyfKAdHpuJVPhbAzGHqpczl) {return !isNaN(parseFloat(cmRPgRLZTnxpAQyfKAdHpuJVPhbAzGHqpczl)) && isFin" ascii
    $s3  = "var j=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function JoHij(SUWFnENCjUZ,xKMBrMjJwklra,DwIIpqpz){TBEO=parseInt(SUWFnENCjUZ,xKMBrMjJwklra);QqFZb=TBEO.toString(DwIIpqpz);return" ascii
    $s5  = "function JoHij(SUWFnENCjUZ,xKMBrMjJwklra,DwIIpqpz){TBEO=parseInt(SUWFnENCjUZ,xKMBrMjJwklra);QqFZb=TBEO.toString(DwIIpqpz);return" ascii
    $s6  = "function QyXdvxFAsEGAgRyRi(YaKjr){TPeGxsCLgoY= '';GNqnkvlTrfj=(-746+746)/112; while(true){if(GNqnkvlTrfj >= (531+463)/497)break;" ascii
    $s7  = "yKPAlQehB[GNqnkvlTrfj]=(-432+432)/4; while(true) { if(yKPAlQehB[GNqnkvlTrfj] > YaKjr[GNqnkvlTrfj].length-(-204+464)/260) { break" ascii
    $s8  = "var j=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "var O=new Array(\"2c\",\"27\",\"2b\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s10 = "function MlzCGOebVga(tTOGArIU,kPuduk){return tTOGArIU.split(kPuduk)}" fullword ascii
    $s11 = ";}GNqnkvlTrfj++;} return TPeGxsCLgoY}" fullword ascii
    $s12 = "var O=new Array(\"2c\",\"27\",\"2b\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s13 = " QqFZb;}function flWOaVpUlJfsMNp(dbPynegIvbWWWlVeS){eval(dbPynegIvbWWWlVeS)}" fullword ascii
    $s14 = "function QiuhcAOHNVIPdmXakOcGHxZDnDlRRfaApGBzgzXERmLstrFCpqajvF(ttDhUVGKvMSCa,awJziZIXnTZSha){ return ywjxH[JoHij(ttDhUVGKvMSCa[" ascii
    $s15 = "function QyXdvxFAsEGAgRyRi(YaKjr){TPeGxsCLgoY= '';GNqnkvlTrfj=(-746+746)/112; while(true){if(GNqnkvlTrfj >= (531+463)/497)break;" ascii
    $s16 = "function QiuhcAOHNVIPdmXakOcGHxZDnDlRRfaApGBzgzXERmLstrFCpqajvF(ttDhUVGKvMSCa,awJziZIXnTZSha){ return ywjxH[JoHij(ttDhUVGKvMSCa[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}