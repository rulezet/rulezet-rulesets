rule sig_20160405_4239fbe8d809a0e18a59e98c567b0678 {
  meta:
    description = "datamaliciousorder - file 20160405_4239fbe8d809a0e18a59e98c567b0678.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10c3d8926cc7edfb512140df73e9491e3adbaac7351a859afbe64170f20f9c6a"

  strings:
    $s1  = "function KlogsrF(YNoI,fiOeP) {" fullword ascii
    $s2  = "return KlogsrF(AU,wSaJA[361-355]+wSaJA[487-480]+wSaJA[813-805]);" fullword ascii
    $s3  = "return dGxWHzg[0] + dGxWHzg[2] + dGxWHzg[4] + \".F\" + dGxWHzg[7] + dGxWHzg[9] + dGxWHzg[12] + dGxWHzg[14];" fullword ascii
    $s4  = "var Nn = true  , ckQv = xyC[7] + xyC[9] + xyC[11];" fullword ascii
    $s5  = "var xyC = (\"2.XMLHTTP uBpPprB DpYFA XML ream St NszWDIvy AD AdMVMZm O qJQh D\").split(\" \");" fullword ascii
    $s6  = "QGCh.open(gABwk,WzNFp,false);" fullword ascii
    $s7  = "function pGcotgdgf(IpOXT) {" fullword ascii
    $s8  = "function sZMm(UWgsD) {" fullword ascii
    $s9  = "function Gsbgn(SIYIWU) {" fullword ascii
    $s10 = "function sfRhizkYp(ecPjWMrHAVj) {" fullword ascii
    $s11 = "function ZGCE(FdRsj) {" fullword ascii
    $s12 = "return LqXIK.status;" fullword ascii
    $s13 = "return new ActiveXObject(LOCn);" fullword ascii
    $s14 = "function mGXPA(VQVDkBij,ssFn) {" fullword ascii
    $s15 = "function RFXWn(MyDDaW) {" fullword ascii
    $s16 = "function gdbV(LqXIK) {" fullword ascii
    $s17 = "return fBM.size;" fullword ascii
    $s18 = "function ZwUzvdHh(KawY) {" fullword ascii
    $s19 = "if(v>=a.length) {break;}" fullword ascii
    $s20 = "if (H >= YbZzV.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}