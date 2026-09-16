rule sig_20160301_f85120c1bb43064cb6fd95226e2c15a4 {
  meta:
    description = "datamaliciousorder - file 20160301_f85120c1bb43064cb6fd95226e2c15a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "419db2a30ac750f5f36ef1bebe2a374e647bfe979aa0961ca794627d7ef0f185"

  strings:
    $s1  = "var aC = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(tDqrb);" fullword ascii
    $s3  = "var Neq = (ovU + \"TTP\" + \" yHazcJP gzVGi XML ream St qaGwbThp AD gYvEKFr OD\").split(\" \");" fullword ascii
    $s4  = "var fK = true  , XPgW = Neq[7] + \"\" + Neq[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + XGzMuGF + \".F\" + rIobhFKzfo + covJd + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "PaXoG.open(zDUho,VPfoO,false);" fullword ascii
    $s7  = "function phzRL(tVdVfY) {" fullword ascii
    $s8  = "function MSdp(OWQsI) {" fullword ascii
    $s9  = "if (((new Date())>0,7543676888)) {" fullword ascii
    $s10 = "BDJ = d; break; " fullword ascii
    $s11 = "function vPcuUZBi() {" fullword ascii
    $s12 = "return new ActiveXObject(tVdVfY);" fullword ascii
    $s13 = "return Ln.ExpandEnvironmentStrings(aC);" fullword ascii
    $s14 = "function AlhctDcel(EdJKh,voaXU,clptL) {" fullword ascii
    $s15 = "function lchk(EuybI,sFSJf) {" fullword ascii
    $s16 = "function bQDJLvirA(MfffUCSGwWn) {" fullword ascii
    $s17 = "function TvMb(PaXoG,VPfoO,zDUho) {" fullword ascii
    $s18 = "function RbOO(SpZDf) {" fullword ascii
    $s19 = "function BLti(JCqCB) {" fullword ascii
    $s20 = "return YJsPT;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}