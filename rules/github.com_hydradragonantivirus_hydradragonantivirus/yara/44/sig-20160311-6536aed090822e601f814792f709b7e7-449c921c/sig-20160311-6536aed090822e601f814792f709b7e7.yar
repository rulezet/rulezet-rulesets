rule sig_20160311_6536aed090822e601f814792f709b7e7 {
  meta:
    description = "datamaliciousorder - file 20160311_6536aed090822e601f814792f709b7e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4ad20788bfecb66890a0265c285ceafe871355661f26b053c08d38d1fbfdbd"

  strings:
    $s1  = "return aMQjIkN[0] + aMQjIkN[2] + aMQjIkN[4] + \".F\" + aMQjIkN[7] + aMQjIkN[9] + aMQjIkN[12] + aMQjIkN[14];" fullword ascii
    $s2  = "var QP = true  , KDkd = bkB[7] + bkB[9] + bkB[11];" fullword ascii
    $s3  = "ztzHd.open(LjfKv,RSHxU,false);" fullword ascii
    $s4  = "var aMQjIkN = \"Sc mezQOLF r ItNbKNsRv ipting rSwLSkj NwP ile YEmIXZKNJqztWT System cH DKSNL Obj htkqfW ect ERxfiIt\".split(\" " ascii
    $s5  = "var bkB = (\"2.XMLHTTP HKgzFaU jWYZi XML ream St LfhOGIAr AD CIazpqa O VSZM D\").split(\" \");" fullword ascii
    $s6  = "function enrO(GBYaF) {" fullword ascii
    $s7  = "function cpTM(mAVbA) {" fullword ascii
    $s8  = "function ucbvz(SDtffq) {" fullword ascii
    $s9  = "function DxeP(YPgCO) {" fullword ascii
    $s10 = "function WGKI(QknBI) {" fullword ascii
    $s11 = "return Rll.size;" fullword ascii
    $s12 = "return PYnADr.position=147-147;" fullword ascii
    $s13 = "function jeDW(dGuaX) {" fullword ascii
    $s14 = "function utBSGfUE(uJaTf,CrvQBM) {" fullword ascii
    $s15 = "KGo = L; break; " fullword ascii
    $s16 = "function CvkfDtNv(Rll) {" fullword ascii
    $s17 = "function jHxe(FEjVe,TERPR) {" fullword ascii
    $s18 = "if (GBYaF > 128758-886){return true;} else {return false;}" fullword ascii
    $s19 = "if (SQrUq == 1175-975){return true;} else {return false;}" fullword ascii
    $s20 = "function bUKKi(PYnADr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}