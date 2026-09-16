rule sig_20151211_3f548dd62d59fe60a78cd0452d148458 {
  meta:
    description = "datamaliciousorder - file 20151211_3f548dd62d59fe60a78cd0452d148458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e021eecd19e45edac357f267a66baf3d7af74e9b3c3c06a59230ea5ecee33302"

  strings:
    $s1  = "function lcxREnW(oBJFNAIaTXEqdpVMdiHvphVeKquqoZngdadl) {return !isNaN(parseFloat(oBJFNAIaTXEqdpVMdiHvphVeKquqoZngdadl)) && isFin" ascii
    $s2  = "function lcxREnW(oBJFNAIaTXEqdpVMdiHvphVeKquqoZngdadl) {return !isNaN(parseFloat(oBJFNAIaTXEqdpVMdiHvphVeKquqoZngdadl)) && isFin" ascii
    $s3  = "function CoCmXgKdKuatasUumbCrXXsSQHhNCgIDrCUQvcNjGlEShOpclnzoHT(lZcuTruhWSbUs,mhVaptdseJOLeX){ return LfSiS[HHJIL(lZcuTruhWSbUs[" ascii
    $s4  = "function uUITeSdxaztorUbWR(WaOns){yDkPCwcvlfv= '';HiIUPLikBDj=(-752+752)/671; while(true){if(HiIUPLikBDj >= (1128+146)/637)break" ascii
    $s5  = "function CoCmXgKdKuatasUumbCrXXsSQHhNCgIDrCUQvcNjGlEShOpclnzoHT(lZcuTruhWSbUs,mhVaptdseJOLeX){ return LfSiS[HHJIL(lZcuTruhWSbUs[" ascii
    $s6  = "function uUITeSdxaztorUbWR(WaOns){yDkPCwcvlfv= '';HiIUPLikBDj=(-752+752)/671; while(true){if(HiIUPLikBDj >= (1128+146)/637)break" ascii
    $s7  = ";TYLHqourx[HiIUPLikBDj]=(-693+693)/446; while(true) { if(TYLHqourx[HiIUPLikBDj] > WaOns[HiIUPLikBDj].length-(-24+822)/798) { bre" ascii
    $s8  = "function ZfvbWdzSsRn(Utugjjto,GxerBZ){return Utugjjto.split(GxerBZ)}" fullword ascii
    $s9  = "var O=new Array(\"2f\",\"2e\",\"29\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s10 = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"39\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var O=new Array(\"2f\",\"2e\",\"29\",\"2b\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"39\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "j]++;}HiIUPLikBDj++;} return yDkPCwcvlfv}" fullword ascii
    $s14 = "function HHJIL(RSjPItlGijG,XRHXtvWMHlObp,MAoUVfTB){QBuj=parseInt(RSjPItlGijG,XRHXtvWMHlObp);PgaHA=QBuj.toString(MAoUVfTB);return" ascii
    $s15 = " PgaHA;}function zkQiIFOGbHUfprq(DiHQuCHQzVJogVKDT){eval(DiHQuCHQzVJogVKDT)}" fullword ascii
    $s16 = "function HHJIL(RSjPItlGijG,XRHXtvWMHlObp,MAoUVfTB){QBuj=parseInt(RSjPItlGijG,XRHXtvWMHlObp);PgaHA=QBuj.toString(MAoUVfTB);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}