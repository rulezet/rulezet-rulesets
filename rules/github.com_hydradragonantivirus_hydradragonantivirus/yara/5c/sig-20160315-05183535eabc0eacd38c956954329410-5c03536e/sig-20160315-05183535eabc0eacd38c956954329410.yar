rule sig_20160315_05183535eabc0eacd38c956954329410 {
  meta:
    description = "datamaliciousorder - file 20160315_05183535eabc0eacd38c956954329410.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d074209f149015ce73e2584d1714c73d4f8916fda2f80ae5a64ce08fc748bba3"

  strings:
    $s1  = "return sqfzCRN[0] + sqfzCRN[2] + sqfzCRN[4] + \".F\" + sqfzCRN[7] + sqfzCRN[9] + sqfzCRN[12] + sqfzCRN[14];" fullword ascii
    $s2  = "var dl = true  , KuLu = KEn[7] + KEn[9] + KEn[11];" fullword ascii
    $s3  = "var sqfzCRN = zZCMQ(\"Sc nncjgDl r dgPfpvnKk ipting rxLdtlg vhV ile XUgmPJesEDGgii System bO eFVfy Obj mEwcFU ect ujopFwM SRVSp" ascii
    $s4  = "var sqfzCRN = zZCMQ(\"Sc nncjgDl r dgPfpvnKk ipting rxLdtlg vhV ile XUgmPJesEDGgii System bO eFVfy Obj mEwcFU ect ujopFwM SRVSp" ascii
    $s5  = "UJBpM.open(mFQhd,KCqgM,false);" fullword ascii
    $s6  = "var KEn = (\"2.XMLHTTP uKNEzQy YHdcp XML ream St tRIDYese AD oeKXvmA O SuvU D\").split(\" \");" fullword ascii
    $s7  = "function LUQYkEylv(yxpQeARydfs) {" fullword ascii
    $s8  = "return bAKNcvi(Nl,RxiFf[366-360]+RxiFf[800-793]+RxiFf[541-533]);" fullword ascii
    $s9  = "if (vIERy > 153559-458){return true;} else {return false;}" fullword ascii
    $s10 = "function bAKNcvi(ctPN,CuKox) {" fullword ascii
    $s11 = "return Mwv.size;" fullword ascii
    $s12 = "function WytD(qKwyu) {" fullword ascii
    $s13 = "return ctPN.ExpandEnvironmentStrings(CuKox);" fullword ascii
    $s14 = "return kvJx.responseBody;" fullword ascii
    $s15 = "function WkFV(ytjiK) {" fullword ascii
    $s16 = "function NdES(vIERy) {" fullword ascii
    $s17 = "function BmaT(HhVxO,DCrYM) {" fullword ascii
    $s18 = "dfc = H; break; " fullword ascii
    $s19 = "function Gfwz(UJBpM,KCqgM,mFQhd) {" fullword ascii
    $s20 = "if (oZwMo == 1102-902){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}