rule sig_20160322_5a500718321888322d587c43dadb16ee {
  meta:
    description = "datamaliciousorder - file 20160322_5a500718321888322d587c43dadb16ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "047857836fffc663b8539a490df68b68209ae9d698e42e79fab4b6cd99e9a409"

  strings:
    $s1  = "return WScript.CreateObject(yufCb);" fullword ascii
    $s2  = "return CytvjxU[0] + CytvjxU[2] + CytvjxU[4] + \".F\" + CytvjxU[7] + CytvjxU[9] + CytvjxU[12] + CytvjxU[14];" fullword ascii
    $s3  = "var pz = true  , RtGT = oRD[7] + oRD[9] + oRD[11];" fullword ascii
    $s4  = "hdgze.open(PaWUi,RaDXe,false);" fullword ascii
    $s5  = "var oRD = (\"2.XMLHTTP UoSVafK VIzTA XML ream St NBimYGyS AD HImhwqI O lmjD D\").split(\" \");" fullword ascii
    $s6  = "var CytvjxU = jUHmh(njVVuRIIRE+\" \"+\"System LM ciVii Obj FHTkkP ect otRVNYB DgveE\", \" \");" fullword ascii
    $s7  = "function FHsn(hdgze,RaDXe,PaWUi) {" fullword ascii
    $s8  = "function QuSstTyCV(RjSWf) {" fullword ascii
    $s9  = "function dUlE(FilIN) {" fullword ascii
    $s10 = "function NLnd(VvKkN) {" fullword ascii
    $s11 = "return moE.split(FqJnu);" fullword ascii
    $s12 = "function mowa(oeLmR) {" fullword ascii
    $s13 = "twD = C; break; " fullword ascii
    $s14 = "return BTXsXbO(vj,PBXzc[392-386]+PBXzc[487-480]+PBXzc[912-904]);" fullword ascii
    $s15 = "if (dwaiF == 444-244){return true;} else {return false;}" fullword ascii
    $s16 = "if(C>=I.length) {break;}" fullword ascii
    $s17 = "return oOFr[phqTOk[0]];" fullword ascii
    $s18 = "return KuF.size;" fullword ascii
    $s19 = "function jUHmh(moE,FqJnu) {" fullword ascii
    $s20 = "function VrRJGeb(oOFr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}