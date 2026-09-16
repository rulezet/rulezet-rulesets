rule sig_20160419_e5d834a8bdd258df16627fb15ad6b71f {
  meta:
    description = "datamaliciousorder - file 20160419_e5d834a8bdd258df16627fb15ad6b71f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c038680e4ede20f45575ec4eb9fe9b6a3288b0b040ab4533f881180082456925"

  strings:
    $s1  = "return PdPtCgq[0] + PdPtCgq[2] + PdPtCgq[4] + \".F\" + PdPtCgq[7] + PdPtCgq[9] + PdPtCgq[12] + PdPtCgq[14];" fullword ascii
    $s2  = "var fU = true  , Rnyc = dhA[7] + dhA[9] + dhA[11];" fullword ascii
    $s3  = "Fmri.open(FMDIn,eXoIt,false);" fullword ascii
    $s4  = "var dhA = (\"2.XMLHTTP zKzoOjm HZnYk XML ream St rmCkbsfC AD bOoYKVu O Rrys D\").split(\" \");" fullword ascii
    $s5  = "if(P>=v.length) {break;}" fullword ascii
    $s6  = "function aCYSH(FYg,CgbyY) {" fullword ascii
    $s7  = "hvI = P; break; " fullword ascii
    $s8  = "function EUxv(SulEJ) {" fullword ascii
    $s9  = "return CKiBhEC;" fullword ascii
    $s10 = "function iFKVVngyg(dcCwQ) {" fullword ascii
    $s11 = "return jkXA[jBNlhGh[0]+jBNlhGh[1]];" fullword ascii
    $s12 = "function RSql(RUDSh,JLSMB) {" fullword ascii
    $s13 = "function yxtU(opbKP) {" fullword ascii
    $s14 = "function Blfm(qwZky) {" fullword ascii
    $s15 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s16 = "return FYg[BGCb[0]](CgbyY);" fullword ascii
    $s17 = "return YIYfFXY(vR,MRbMvE+yNrTi[580-572]);" fullword ascii
    $s18 = "return lIkOIdo[0];" fullword ascii
    $s19 = "function CxQO(AOrNc) {" fullword ascii
    $s20 = "if (Q >= SulEJ.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}