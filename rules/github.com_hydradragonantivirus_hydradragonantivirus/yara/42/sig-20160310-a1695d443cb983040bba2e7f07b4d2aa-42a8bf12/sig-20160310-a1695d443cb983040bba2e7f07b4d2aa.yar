rule sig_20160310_a1695d443cb983040bba2e7f07b4d2aa {
  meta:
    description = "datamaliciousorder - file 20160310_a1695d443cb983040bba2e7f07b4d2aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f7ad91225e47d45e699c3fd156b8306019fd50cbe6acb61583130029eb05a9"

  strings:
    $s1  = "return kDzoWju[0] + kDzoWju[2] + kDzoWju[4] + \".F\" + kDzoWju[7] + kDzoWju[9] + kDzoWju[12] + kDzoWju[14];" fullword ascii
    $s2  = "var BZ = true  , sGml = UlN[7] + UlN[9] + UlN[11];" fullword ascii
    $s3  = "var UlN = (\"2.XMLHTTP DrkVjLP XwgiG XML ream St ZalluJGm AD eZeudJr O dWlN D\").split(\" \");" fullword ascii
    $s4  = "AIeZP.open(xORGB,dKzon,false);" fullword ascii
    $s5  = "var kDzoWju = \"Sc eGvpWtd r kRzucxlro ipting nmZOBxk POc ile HoTUCjcpRbHgFS System it MUCgY Obj rMfIre ect EOKmYMq\".split(\" " ascii
    $s6  = "function QmJBqXzB(Xbx) {" fullword ascii
    $s7  = "function ohcDNXqhl(KRmqG,tuXUI,BXQJj,qYHK) {" fullword ascii
    $s8  = "return new ActiveXObject(eTUVhE);" fullword ascii
    $s9  = "if(V>=v.length) {break;}" fullword ascii
    $s10 = "function nnEYmzUE(mhlOP,kvASMZ) {" fullword ascii
    $s11 = "function qiXHXSQWw(BsnMUKMSOIW) {" fullword ascii
    $s12 = "if (vAqQA == 1031-831){return true;} else {return false;}" fullword ascii
    $s13 = "function hbFG(vAqQA) {" fullword ascii
    $s14 = "function rEwn(QBqtF,aqaYT) {" fullword ascii
    $s15 = "return Xbx.size;" fullword ascii
    $s16 = "return teTExaj" fullword ascii
    $s17 = "return JDwME;" fullword ascii
    $s18 = "return WTrIoR.position=485-485;" fullword ascii
    $s19 = "if (pZxvJ > 191045-853){return true;} else {return false;}" fullword ascii
    $s20 = "function uGff(yHQpc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}