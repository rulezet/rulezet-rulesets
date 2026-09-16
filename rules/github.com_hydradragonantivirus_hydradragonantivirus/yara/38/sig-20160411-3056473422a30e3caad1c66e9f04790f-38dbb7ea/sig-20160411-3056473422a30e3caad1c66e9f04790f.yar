rule sig_20160411_3056473422a30e3caad1c66e9f04790f {
  meta:
    description = "datamaliciousorder - file 20160411_3056473422a30e3caad1c66e9f04790f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "920ec87bfcfda09f942cf9bd474e7a2d8614babe9d8fdd7fae44035e66ecf683"

  strings:
    $s1  = "return jMfhtgO[0] + jMfhtgO[2] + jMfhtgO[4] + \".F\" + jMfhtgO[7] + jMfhtgO[9] + jMfhtgO[12] + jMfhtgO[14];" fullword ascii
    $s2  = "var lj = true  , yhUF = zAu[7] + zAu[9] + zAu[11];" fullword ascii
    $s3  = "var zAu = (\"2.XMLHTTP VCyPjAC riiMt XML ream St OkiEHpse AD JgtLNjI O qrQH D\").split(\" \");" fullword ascii
    $s4  = "hcJr.open(OffzU,ADdgq,false);" fullword ascii
    $s5  = "if(Q>=R.length) {break;}" fullword ascii
    $s6  = "function yCrV(HymaJ,ADdgq,OffzU) {" fullword ascii
    $s7  = "return Vdg.size;" fullword ascii
    $s8  = "if (zSFkv > 182372-300){return true;} else {return false;}" fullword ascii
    $s9  = "return nkCtZm[ztvX[744-744]]=207-207;" fullword ascii
    $s10 = "if (QteRz == 456-256){return true;} else {return false;}" fullword ascii
    $s11 = "function MyTC(yMOCD) {" fullword ascii
    $s12 = "function lKBI(XNEqb) {" fullword ascii
    $s13 = "function Bmaq(trbTp,oBcOL) {" fullword ascii
    $s14 = "function kziHRu(GRnpmIF) {" fullword ascii
    $s15 = "function JQNod(eXX,uTCcQ) {" fullword ascii
    $s16 = "function kcIs(onyMu) {" fullword ascii
    $s17 = "function FPQY(zSFkv) {" fullword ascii
    $s18 = "return ZPSi[fiZmHbi[0]+fiZmHbi[1]];" fullword ascii
    $s19 = "function bunfPZpse(XhUoTuBPmWi) {" fullword ascii
    $s20 = "return XNEqb.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}