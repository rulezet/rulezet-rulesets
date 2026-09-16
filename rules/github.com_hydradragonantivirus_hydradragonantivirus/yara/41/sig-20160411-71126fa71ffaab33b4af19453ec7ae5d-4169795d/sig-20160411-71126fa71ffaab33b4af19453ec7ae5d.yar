rule sig_20160411_71126fa71ffaab33b4af19453ec7ae5d {
  meta:
    description = "datamaliciousorder - file 20160411_71126fa71ffaab33b4af19453ec7ae5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82f8573bf45086f60409f7c14df7be1f0bf56aa9dfa486208834913631c2e5fc"

  strings:
    $s1  = "var tq = true  , Uuyf = wuG[7] + wuG[9] + wuG[11];" fullword ascii
    $s2  = "return icDwoVy[0] + icDwoVy[2] + icDwoVy[4] + \".F\" + icDwoVy[7] + icDwoVy[9] + icDwoVy[12] + icDwoVy[14];" fullword ascii
    $s3  = "var wuG = (\"2.XMLHTTP mUxTXnw NXrye XML ream St uemnHUkB AD ZBZZBSc O wcMs D\").split(\" \");" fullword ascii
    $s4  = "FXxF.open(lDqLj,Gdtgj,false);" fullword ascii
    $s5  = "if(U>=S.length) {break;}" fullword ascii
    $s6  = "return SZyV[qCPLUxc[0]+qCPLUxc[1]];" fullword ascii
    $s7  = "return hBnYa;" fullword ascii
    $s8  = "return RSscEdJ[0];" fullword ascii
    $s9  = "return ZPr[Sstj[0]](hSwFU);" fullword ascii
    $s10 = "function IUHs(QJQoJ) {" fullword ascii
    $s11 = "function xMpsywXLc(CgmNeyDNpsJ) {" fullword ascii
    $s12 = "function ebvN(hsybw) {" fullword ascii
    $s13 = "function jgDjL(ZPr,hSwFU) {" fullword ascii
    $s14 = "function hncpZ(TISSXx) {" fullword ascii
    $s15 = "function yEui(exNWS,gMyBj) {" fullword ascii
    $s16 = "if (rgmAp > 151599-809){return true;} else {return false;}" fullword ascii
    $s17 = "function wDqg(LYvfu) {" fullword ascii
    $s18 = "IPy = U; break; " fullword ascii
    $s19 = "function vwZGGh(gtOJ,FCwrcL) {" fullword ascii
    $s20 = "function ajUMExPW(vwSU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}