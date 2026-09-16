rule sig_20160307_f8fc41cc5d58335e5d353c4466f8a8c6 {
  meta:
    description = "datamaliciousorder - file 20160307_f8fc41cc5d58335e5d353c4466f8a8c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b19f939fd1fb490988bcd9ec9654bce7665d4cde824f037447d8dcd0b258c60"

  strings:
    $s1  = "var tbP = (\"2.XMLHTTP xKGxTeT wgUMn XML ream St Eyelaecw AD lprrMSv O RiZP D\").split(\" \");" fullword ascii
    $s2  = "return qXgKlbJ[0] + qXgKlbJ[2] + qXgKlbJ[4] + \".F\" + qXgKlbJ[7] + qXgKlbJ[9] + qXgKlbJ[12] + qXgKlbJ[14];" fullword ascii
    $s3  = "var Ba = true  , Snlq = tbP[7] + tbP[9] + tbP[11];" fullword ascii
    $s4  = "var qXgKlbJ = \"Sc LhyyHXd r uHixKpWQg ipting OWfEVLX Mom ile ocyofPWeQhjZtM System Kl WSaVj Obj UmoOEw ect UxtJDbh\".split(\" " ascii
    $s5  = "xcwXi.open(lApew,sJGCd,false);" fullword ascii
    $s6  = "function SmCX(WfIgL) {" fullword ascii
    $s7  = "function nJwR(bkHsh) {" fullword ascii
    $s8  = "pzo = e; break; " fullword ascii
    $s9  = "return mPSVj.status;" fullword ascii
    $s10 = "function ZtrGvkqW(syp) {" fullword ascii
    $s11 = "return woTpScx" fullword ascii
    $s12 = "function TTtj(mPSVj) {" fullword ascii
    $s13 = "function DVZi(IcjBN) {" fullword ascii
    $s14 = "function QJHz(bDTNE,fOeGA) {" fullword ascii
    $s15 = "if(e>=Z.length) {break;}" fullword ascii
    $s16 = "function LroR(xcwXi,sJGCd,lApew) {" fullword ascii
    $s17 = "function qjwn(jAVYa) {" fullword ascii
    $s18 = "function FNMd(Qtdey) {" fullword ascii
    $s19 = "function AqjpN(vEvSmi) {" fullword ascii
    $s20 = "if (v >= YwCkh.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}