rule sig_20160405_4370841c0c8878d2547c5067b7b64ddd {
  meta:
    description = "datamaliciousorder - file 20160405_4370841c0c8878d2547c5067b7b64ddd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41ec691e2c037f6fa0db140d9040997c411a0081f99e89c5b8bb2340cdc81908"

  strings:
    $s1  = "return FNYtpKt[0] + FNYtpKt[2] + FNYtpKt[4] + \".F\" + FNYtpKt[7] + FNYtpKt[9] + FNYtpKt[12] + FNYtpKt[14];" fullword ascii
    $s2  = "var ZY = true  , unpE = Bug[7] + Bug[9] + Bug[11];" fullword ascii
    $s3  = "var Bug = (\"2.XMLHTTP MFtYYDM Bgdbw XML ream St OFvQJMzt AD UyZnxFl O TPId D\").split(\" \");" fullword ascii
    $s4  = "FYHD.open(AYOSn,sPuKg,false);" fullword ascii
    $s5  = "if(J>=x.length) {break;}" fullword ascii
    $s6  = "xxJ = J; break; " fullword ascii
    $s7  = "var LiUqziQ = \"KtcdRY*qDJ*pt.S\"+\"hell*RYZopCr*Scri*\";" fullword ascii
    $s8  = "return \"XFOAdjLpapwyoR\";" fullword ascii
    $s9  = "return new ActiveXObject(EOMl);" fullword ascii
    $s10 = "function rstLc(KSQmMd) {" fullword ascii
    $s11 = "function UnJNbumiJ(LdEWP) {" fullword ascii
    $s12 = "function JyGw(plqQj) {" fullword ascii
    $s13 = "function beeTGcpTI(VybSwiiJYKb) {" fullword ascii
    $s14 = "function iXzh(aAAaE) {" fullword ascii
    $s15 = "function rHqiA(aXcygTrJ,hJEg) {" fullword ascii
    $s16 = "return TTbQocQ;" fullword ascii
    $s17 = "return aAAaE.status;" fullword ascii
    $s18 = "function Gzxjd(UiYRxs) {" fullword ascii
    $s19 = "return mZNG[wFjOVW[0]];" fullword ascii
    $s20 = "function ibPO(uZhuC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}