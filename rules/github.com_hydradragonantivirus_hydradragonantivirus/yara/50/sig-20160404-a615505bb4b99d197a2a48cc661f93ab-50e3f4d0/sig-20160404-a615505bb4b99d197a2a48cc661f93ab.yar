rule sig_20160404_a615505bb4b99d197a2a48cc661f93ab {
  meta:
    description = "datamaliciousorder - file 20160404_a615505bb4b99d197a2a48cc661f93ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3a0e4b6ed7f4fd8583d6ab588350793ee0d056af5161f341a2ec4544b1980e3"

  strings:
    $s1  = "njPW.open(eexLE,GkrCY,false);" fullword ascii
    $s2  = "function diPyr(JFPlaMha,gcMV) {" fullword ascii
    $s3  = "function UKHM(ZiJWn) {" fullword ascii
    $s4  = "function UpSoYJzB(GSPG) {" fullword ascii
    $s5  = "return NdValmx;" fullword ascii
    $s6  = "return ZgSJCca[0] + ZgSJCca[2] + ZgSJCca[4] + \".F\" + ZgSJCca[7] + ZgSJCca[9] + ZgSJCca[12] + ZgSJCca[14];" fullword ascii
    $s7  = "function nmhiDsqa(NPo) {" fullword ascii
    $s8  = "function wAgbB(tjWkwy) {" fullword ascii
    $s9  = "function GhBPFfhUe(qjCjHjqmpep) {" fullword ascii
    $s10 = "function FhVY(vxWkB) {" fullword ascii
    $s11 = "function QIIBuJNES(KWawF) {" fullword ascii
    $s12 = "return \"lWWUqOMfkWgmQU\";" fullword ascii
    $s13 = "function DYEt(nkMIY,wPukx) {" fullword ascii
    $s14 = "return bJPRj;" fullword ascii
    $s15 = "Jkb = H; break; " fullword ascii
    $s16 = "return FPKUn.status;" fullword ascii
    $s17 = "return new ActiveXObject(hOdp);" fullword ascii
    $s18 = "var MV = true  , phbe = lcA[7] + lcA[9] + lcA[11];" fullword ascii
    $s19 = "var wMlCUmh = \"KywLTr*bpS*pt.S\"+\"hell*taNpTwH*Scri*\";" fullword ascii
    $s20 = "function RicX(GMLkS,GkrCY,eexLE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}