rule sig_20160311_dba4d95912f3cefb1230bc318848e38e {
  meta:
    description = "datamaliciousorder - file 20160311_dba4d95912f3cefb1230bc318848e38e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a71180662b6edd25db6b7456af81e7a3dd62b317b39e376a7be1483e90079cae"

  strings:
    $s1  = "return JrMYBDw[0] + JrMYBDw[2] + JrMYBDw[4] + \".F\" + JrMYBDw[7] + JrMYBDw[9] + JrMYBDw[12] + JrMYBDw[14];" fullword ascii
    $s2  = "var DJ = true  , cNbh = lXq[7] + lXq[9] + lXq[11];" fullword ascii
    $s3  = "KtMiW.open(NDgmC,coaHj,false);" fullword ascii
    $s4  = "var JrMYBDw = \"Sc DAMInxw r UFTfdsUan ipting PKSZxKT KFi ile LJLRXdwuHkSmnM System jt dUdWQ Obj yMdPJM ect awzOAsN\".split(\" " ascii
    $s5  = "var lXq = (\"2.XMLHTTP beCxFck qVNjd XML ream St tEWrgJWK AD FrTymcB O pUnU D\").split(\" \");" fullword ascii
    $s6  = "function tkrF(PGAEY) {" fullword ascii
    $s7  = "function IpjuUsHtP() {" fullword ascii
    $s8  = "return HPovLU.position=111-111;" fullword ascii
    $s9  = "function VHRi(ScbdK,WjaMI) {" fullword ascii
    $s10 = "function NOTB(KtMiW,coaHj,NDgmC) {" fullword ascii
    $s11 = "function fhywzAg(VrsR) {" fullword ascii
    $s12 = "function GViq(PZydV) {" fullword ascii
    $s13 = "return maPhANB" fullword ascii
    $s14 = "function YBsW(SfPqM) {" fullword ascii
    $s15 = "if (jZSso > 140179-305){return true;} else {return false;}" fullword ascii
    $s16 = "function LYGKuThn(mKN) {" fullword ascii
    $s17 = "return VrsR.responseBody;" fullword ascii
    $s18 = "if (SfPqM == 1036-836){return true;} else {return false;}" fullword ascii
    $s19 = "if (k >= PuFNV.length) {break;}" fullword ascii
    $s20 = "function GYZV(jZSso) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}