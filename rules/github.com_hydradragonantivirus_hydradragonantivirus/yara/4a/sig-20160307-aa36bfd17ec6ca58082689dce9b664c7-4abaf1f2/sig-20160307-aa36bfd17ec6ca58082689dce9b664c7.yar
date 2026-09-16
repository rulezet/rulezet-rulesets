rule sig_20160307_aa36bfd17ec6ca58082689dce9b664c7 {
  meta:
    description = "datamaliciousorder - file 20160307_aa36bfd17ec6ca58082689dce9b664c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f9a54596b91cf21ecb1e5c4fd810410e0ab2335f396d97bad7b55f6b3b639f"

  strings:
    $s1  = "var Ul = true  , jHfZ = LGG[7] + LGG[9] + LGG[11];" fullword ascii
    $s2  = "return YIalzxJ[0] + YIalzxJ[2] + YIalzxJ[4] + \".F\" + YIalzxJ[7] + YIalzxJ[9] + YIalzxJ[12] + YIalzxJ[14];" fullword ascii
    $s3  = "Kqplh.open(iRtlj,ShGWj,false);" fullword ascii
    $s4  = "var YIalzxJ = \"Sc anhUXFh r IAdJJresN ipting cCUXfGS ldA ile fGscFHcLlocVgo System eq PqabI Obj jEBFas ect JJRerVW\".split(\" " ascii
    $s5  = "var LGG = (\"2.XMLHTTP SCtehPL DTLoN XML ream St XONWPlmP AD pWamCPo O ojwx D\").split(\" \");" fullword ascii
    $s6  = "if (vjZwr > 189952-539){return true;} else {return false;}" fullword ascii
    $s7  = "function ZPJx(nbWFP) {" fullword ascii
    $s8  = "function uTfsvre(xzyr) {" fullword ascii
    $s9  = "function dQwxK(fPkCKC) {" fullword ascii
    $s10 = "function dJQBmyqPQ(qRNlvJqYtqH) {" fullword ascii
    $s11 = "return CECdi.status;" fullword ascii
    $s12 = "function WMxj(jWUvk) {" fullword ascii
    $s13 = "if (((new Date())>0,750730888)) {" fullword ascii
    $s14 = "function foLv(vjZwr) {" fullword ascii
    $s15 = "function OVUu(dFLFA) {" fullword ascii
    $s16 = "return mXAzy.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s17 = "function sKKV(CECdi) {" fullword ascii
    $s18 = "if (I >= LuqQJ.length) {break;}" fullword ascii
    $s19 = "return FYQ.size;" fullword ascii
    $s20 = "return DD.ExpandEnvironmentStrings(vGLqC[6]+vGLqC[7]+vGLqC[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}