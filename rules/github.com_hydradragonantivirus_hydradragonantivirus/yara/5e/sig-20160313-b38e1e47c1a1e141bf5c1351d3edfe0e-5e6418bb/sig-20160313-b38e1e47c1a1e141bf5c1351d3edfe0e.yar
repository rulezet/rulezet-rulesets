rule sig_20160313_b38e1e47c1a1e141bf5c1351d3edfe0e {
  meta:
    description = "datamaliciousorder - file 20160313_b38e1e47c1a1e141bf5c1351d3edfe0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdfa5c35dd76162af54587fe43481c6e14d68d4ed0090abbca00b1bb12556803"

  strings:
    $s1  = "return WXndHIK[0] + WXndHIK[2] + WXndHIK[4] + \".F\" + WXndHIK[7] + WXndHIK[9] + WXndHIK[12] + WXndHIK[14];" fullword ascii
    $s2  = "var aL = true  , bjVo = UCF[7] + UCF[9] + UCF[11];" fullword ascii
    $s3  = "ocIBP.open(BTRXY,HVVqf,false);" fullword ascii
    $s4  = "var UCF = (\"2.XMLHTTP rildedn jOxGD XML ream St bkjCtpDr AD FJxEeRm O fKEG D\").split(\" \");" fullword ascii
    $s5  = "var WXndHIK = \"Sc nGQlQvH r lCgLzPJTm ipting ondUUCI vzY ile SmBuRWdNVUXkku System Dq fliUm Obj rfPLBS ect xbLuDSO\".split(\" " ascii
    $s6  = "if(U>=J.length) {break;}" fullword ascii
    $s7  = "if (h >= wgRfC.length) {break;}" fullword ascii
    $s8  = "KyU = U; break; " fullword ascii
    $s9  = "return new ActiveXObject(JNKCjE);" fullword ascii
    $s10 = "function gIUrtsh(jtAz) {" fullword ascii
    $s11 = "function SPBB(Cghut) {" fullword ascii
    $s12 = "if (OExxQ == 1169-969){return true;} else {return false;}" fullword ascii
    $s13 = "return hEuMAJr(qp,lDCus[201-195]+lDCus[382-375]+lDCus[495-487]);" fullword ascii
    $s14 = "return JtRfc;" fullword ascii
    $s15 = "function QMefh(sFVcuc) {" fullword ascii
    $s16 = "return hxo.size;" fullword ascii
    $s17 = "if (wZgIU > 193896-635){return true;} else {return false;}" fullword ascii
    $s18 = "function bGWN(wgRfC) {" fullword ascii
    $s19 = "return hlKCnre" fullword ascii
    $s20 = "function AEOl(GeAba,iwdIv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}