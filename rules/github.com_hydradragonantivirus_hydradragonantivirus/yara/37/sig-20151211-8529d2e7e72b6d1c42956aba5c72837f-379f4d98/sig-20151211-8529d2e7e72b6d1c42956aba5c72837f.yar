rule sig_20151211_8529d2e7e72b6d1c42956aba5c72837f {
  meta:
    description = "datamaliciousorder - file 20151211_8529d2e7e72b6d1c42956aba5c72837f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c6337af85e74cc7fe064007ed0c096bb7b95f82f337df9d210945791cd3d10b"

  strings:
    $s1  = "function atVsVxx(yGqMjnDIeUViLrQadSseQhWGfmRrRCBJGoXv) {return !isNaN(parseFloat(yGqMjnDIeUViLrQadSseQhWGfmRrRCBJGoXv)) && isFin" ascii
    $s2  = "function atVsVxx(yGqMjnDIeUViLrQadSseQhWGfmRrRCBJGoXv) {return !isNaN(parseFloat(yGqMjnDIeUViLrQadSseQhWGfmRrRCBJGoXv)) && isFin" ascii
    $s3  = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4d\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function AvApmGYktZgnrrQar(ihRWO){TXtTxRXmevu= '';SoQxZnMnSWo=(-865+865)/354; while(true){if(SoQxZnMnSWo >= (837+823)/830)break;" ascii
    $s5  = "++;}SoQxZnMnSWo++;} return TXtTxRXmevu}" fullword ascii
    $s6  = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4d\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "var d=new Array(\"2c\",\"2b\",\"2a\",\"27\",\"2c\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "function nYmjy(LzoAPEywHxw,GZwCbxZZRBeZn,iUrusobe){FJKx=parseInt(LzoAPEywHxw,GZwCbxZZRBeZn);wVMpo=FJKx.toString(iUrusobe);return" ascii
    $s9  = "function nYmjy(LzoAPEywHxw,GZwCbxZZRBeZn,iUrusobe){FJKx=parseInt(LzoAPEywHxw,GZwCbxZZRBeZn);wVMpo=FJKx.toString(iUrusobe);return" ascii
    $s10 = "var d=new Array(\"2c\",\"2b\",\"2a\",\"27\",\"2c\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = " wVMpo;}function TqAlUbRTHUvBjBB(vgJyTiwMLUJifiVMR){eval(vgJyTiwMLUJifiVMR)}" fullword ascii
    $s12 = "function OrmhvvkvBUi(VYEAFXvm,LGdOwz){return VYEAFXvm.split(LGdOwz)}" fullword ascii
    $s13 = "function AvApmGYktZgnrrQar(ihRWO){TXtTxRXmevu= '';SoQxZnMnSWo=(-865+865)/354; while(true){if(SoQxZnMnSWo >= (837+823)/830)break;" ascii
    $s14 = "khbJWnPoT[SoQxZnMnSWo]=(-541+541)/541; while(true) { if(khbJWnPoT[SoQxZnMnSWo] > ihRWO[SoQxZnMnSWo].length-(225+193)/418) { brea" ascii
    $s15 = "function ALZNgvjLWEIQTLcEVFfTSOhqzYBhZPPSGYDMAOhXUgzdbCDcBcejpz(zMrgpCaVEXwEg,AaWWwAJnuIHTJp){ return JMpLc[nYmjy(zMrgpCaVEXwEg[" ascii
    $s16 = "function ALZNgvjLWEIQTLcEVFfTSOhqzYBhZPPSGYDMAOhXUgzdbCDcBcejpz(zMrgpCaVEXwEg,AaWWwAJnuIHTJp){ return JMpLc[nYmjy(zMrgpCaVEXwEg[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}