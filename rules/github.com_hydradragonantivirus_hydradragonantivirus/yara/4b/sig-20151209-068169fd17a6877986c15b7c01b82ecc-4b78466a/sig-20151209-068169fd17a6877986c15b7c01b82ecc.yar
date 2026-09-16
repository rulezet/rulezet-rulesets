rule sig_20151209_068169fd17a6877986c15b7c01b82ecc {
  meta:
    description = "datamaliciousorder - file 20151209_068169fd17a6877986c15b7c01b82ecc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "335443cb8ec4a1b43de58743730f88d084f9ec8756766eb4071dd663b1e3b1c6"

  strings:
    $s1  = "function BWSzpOq(mYKPKeTyfyHRovzDcSeOdTSRRkQMxZOFDDia) {return !isNaN(parseFloat(mYKPKeTyfyHRovzDcSeOdTSRRkQMxZOFDDia)) && isFin" ascii
    $s2  = "function BWSzpOq(mYKPKeTyfyHRovzDcSeOdTSRRkQMxZOFDDia) {return !isNaN(parseFloat(mYKPKeTyfyHRovzDcSeOdTSRRkQMxZOFDDia)) && isFin" ascii
    $s3  = " RhRoc;}function MoWTwTROtziZdKR(NRylizIkXTuPCEvtc){eval(NRylizIkXTuPCEvtc)}" fullword ascii
    $s4  = "} return VyJnHcmPsLS}" fullword ascii
    $s5  = "function dLfxg(EtRqZQKASIr,lTNhGeWcYiaGh,GwsjMwJq){BcJy=parseInt(EtRqZQKASIr,lTNhGeWcYiaGh);RhRoc=BcJy.toString(GwsjMwJq);return" ascii
    $s6  = "function SDxrPHsKzfu(rvwOotVr,vLMYnr){return rvwOotVr.split(vLMYnr)}" fullword ascii
    $s7  = "function xtJsMnbdzKEEtOfWyLuUtPzoxDDqkFHSqPoCuZQwxFZZZCIMruuQov(eFpGVHEzgpUwk,WjxYKvpqLAteTw){ return cVHXM[dLfxg(eFpGVHEzgpUwk[" ascii
    $s8  = "xpikDug[zlAuNdjsXRl]=(-630+630)/590; while(true) { if(yDxpikDug[zlAuNdjsXRl] > ztEZN[zlAuNdjsXRl].length-(104+334)/438) { break;" ascii
    $s9  = "function KwRtvSHWjTvWqhlLb(ztEZN){VyJnHcmPsLS= '';for(zlAuNdjsXRl=(-669+669)/2; zlAuNdjsXRl < (1044+140)/592; zlAuNdjsXRl++) {yD" ascii
    $s10 = "function KwRtvSHWjTvWqhlLb(ztEZN){VyJnHcmPsLS= '';for(zlAuNdjsXRl=(-669+669)/2; zlAuNdjsXRl < (1044+140)/592; zlAuNdjsXRl++) {yD" ascii
    $s11 = "function dLfxg(EtRqZQKASIr,lTNhGeWcYiaGh,GwsjMwJq){BcJy=parseInt(EtRqZQKASIr,lTNhGeWcYiaGh);RhRoc=BcJy.toString(GwsjMwJq);return" ascii
    $s12 = "function xtJsMnbdzKEEtOfWyLuUtPzoxDDqkFHSqPoCuZQwxFZZZCIMruuQov(eFpGVHEzgpUwk,WjxYKvpqLAteTw){ return cVHXM[dLfxg(eFpGVHEzgpUwk[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}