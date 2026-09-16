rule sig_20151209_862fb3242dfd22c8f2a6bfc7d75d4a41 {
  meta:
    description = "datamaliciousorder - file 20151209_862fb3242dfd22c8f2a6bfc7d75d4a41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b299b4515d63ca652db0d3f2930a6c5fac7b35cdbc2bf6cc1cc6ee042d96d70"

  strings:
    $s1  = "function VZHrRCo(CoyXBVwJiRChxrAQCWupYGACxrFmVKsYopYT) {return !isNaN(parseFloat(CoyXBVwJiRChxrAQCWupYGACxrFmVKsYopYT)) && isFin" ascii
    $s2  = "function VZHrRCo(CoyXBVwJiRChxrAQCWupYGACxrFmVKsYopYT) {return !isNaN(parseFloat(CoyXBVwJiRChxrAQCWupYGACxrFmVKsYopYT)) && isFin" ascii
    $s3  = ";}} return iURYcGYtpoW}" fullword ascii
    $s4  = "aKNTnfDaN[VKVlFKyUUNz]=(-968+968)/218; while(true) { if(aKNTnfDaN[VKVlFKyUUNz] > axPFX[VKVlFKyUUNz].length-(543+407)/950) { brea" ascii
    $s5  = "function rUYYPorRyiaunwNec(axPFX){iURYcGYtpoW= '';for(VKVlFKyUUNz=(-744+744)/299; VKVlFKyUUNz < (1254+288)/771; VKVlFKyUUNz++) {" ascii
    $s6  = "function wglpiHTOygU(nCVMKSfN,NALhOK){return nCVMKSfN.split(NALhOK)}" fullword ascii
    $s7  = "function rUYYPorRyiaunwNec(axPFX){iURYcGYtpoW= '';for(VKVlFKyUUNz=(-744+744)/299; VKVlFKyUUNz < (1254+288)/771; VKVlFKyUUNz++) {" ascii
    $s8  = "function dHQDDFTVRAxyTlMTZJDAKKtxcqQLlpWxamzCiIrVFBcSDAdHIKbZjz(AUFxRQKQIFpqU,ycxCBonNzjWdDH){ return iJAXu[HjUbB(AUFxRQKQIFpqU[" ascii
    $s9  = "function dHQDDFTVRAxyTlMTZJDAKKtxcqQLlpWxamzCiIrVFBcSDAdHIKbZjz(AUFxRQKQIFpqU,ycxCBonNzjWdDH){ return iJAXu[HjUbB(AUFxRQKQIFpqU[" ascii
    $s10 = " WmWgV;}function tiakHJaOCzGvsKS(mGOxhNEEucakZwpEv){eval(mGOxhNEEucakZwpEv)}" fullword ascii
    $s11 = "function HjUbB(vbdrBvpQufl,FcyZPFwuWPBqN,SoBGBOBb){bqCa=parseInt(vbdrBvpQufl,FcyZPFwuWPBqN);WmWgV=bqCa.toString(SoBGBOBb);return" ascii
    $s12 = "function HjUbB(vbdrBvpQufl,FcyZPFwuWPBqN,SoBGBOBb){bqCa=parseInt(vbdrBvpQufl,FcyZPFwuWPBqN);WmWgV=bqCa.toString(SoBGBOBb);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}