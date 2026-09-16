rule sig_20151208_d5f2a5bb079e8a6561b811a8ee8ed735 {
  meta:
    description = "datamaliciousorder - file 20151208_d5f2a5bb079e8a6561b811a8ee8ed735.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "427beaf2515ae3a1832bbcb0c8a4c9eb5ba75928c7f4db5407abf06ee06cc4b2"

  strings:
    $s1  = "function xrkdFMC(qeVvFcYEWGeqBGZzzNJjZvmNMBkwoDElvvRI) {return !isNaN(parseFloat(qeVvFcYEWGeqBGZzzNJjZvmNMBkwoDElvvRI)) && isFin" ascii
    $s2  = "push(\"108\");i.push(\"117\");i.push(\"100\");i.push(\"101\");i.push(\"115\");i.push(\"47\");i.push(\"112\");i.push(\"111\");i.p" ascii
    $s3  = "function xrkdFMC(qeVvFcYEWGeqBGZzzNJjZvmNMBkwoDElvvRI) {return !isNaN(parseFloat(qeVvFcYEWGeqBGZzzNJjZvmNMBkwoDElvvRI)) && isFin" ascii
    $s4  = "push(\"52\");i.push(\"48\");i.push(\"54\");i.push(\"51\");i.push(\"54\");i.push(\"53\");i.push(\"57\");i.push(\"54\");i.push(\"1" ascii
    $s5  = "function cJBSPvlwbaxQRlisj(RLpmG){ZSsDqYHNzjy= '';for(nHOaAfHGbpl=(-51+51)/733; nHOaAfHGbpl < (1526+194)/860; nHOaAfHGbpl++) {TF" ascii
    $s6  = "dcELuwn[nHOaAfHGbpl]=(-923+923)/338; while(true) { if(TFdcELuwn[nHOaAfHGbpl] > RLpmG[nHOaAfHGbpl].length-(-483+940)/457) { break" ascii
    $s7  = "function cJBSPvlwbaxQRlisj(RLpmG){ZSsDqYHNzjy= '';for(nHOaAfHGbpl=(-51+51)/733; nHOaAfHGbpl < (1526+194)/860; nHOaAfHGbpl++) {TF" ascii
    $s8  = "push(\"95\");i.push(\"112\");i.push(\"97\");i.push(\"103\");i.push(\"101\");i.push(\"115\");i.push(\"95\");i.push(\"115\");i.pus" ascii
    $s9  = "xlOoC)}function mBXqS(HuBRazSmBvh,VhHMiNQqlVULu,wMrBmogp){nfCo=parseInt(HuBRazSmBvh,VhHMiNQqlVULu);zpfyC=nfCo.toString(wMrBmogp)" ascii
    $s10 = "push(\"116\");V.push(\"114\");V.push(\"121\");V.push(\"32\");V.push(\"32\");V.push(\"123\");V.push(\"13\");V.push(\"10\");V.push" ascii
    $s11 = "function tcZMrOXRGWCfFqUlcgRZwYtiFPeEVVMDuTFTdHngtOARSOFdfJmdKj(RJwljHNYQoJef,FceKqwzSqrBVUf){ return cMyWfDCzojtkH[mBXqS(RJwljH" ascii
    $s12 = ";return zpfyC;}function CImEESSeuuqlNva(ENBJxkCIfeDpLbDLy){eval(ENBJxkCIfeDpLbDLy)}" fullword ascii
    $s13 = "function tcZMrOXRGWCfFqUlcgRZwYtiFPeEVVMDuTFTdHngtOARSOFdfJmdKj(RJwljHNYQoJef,FceKqwzSqrBVUf){ return cMyWfDCzojtkH[mBXqS(RJwljH" ascii
    $s14 = "function EoIDHWXKCbO(SDHEXngU,EsmKhE){return SDHEXngU.split(EsmKhE)}" fullword ascii
    $s15 = "push(\"61\");V.push(\"32\");V.push(\"49\");V.push(\"41\");V.push(\"32\");V.push(\"32\");V.push(\"123\");V.push(\"13\");V.push(\"" ascii
    $s16 = "push(\"99\");V.push(\"108\");V.push(\"111\");V.push(\"115\");V.push(\"101\");V.push(\"40\");V.push(\"41\");V.push(\"59\");V.push" ascii
    $s17 = "var cMyWfDCzojtkH=[];for(qjxlOoC=(-450+450)/449;qjxlOoC<(66779+805)/528;qjxlOoC++){cMyWfDCzojtkH[qjxlOoC]=String.fromCharCode(qj" ascii
    $s18 = "push(\"79\");i.push(\"68\");i.push(\"34\");i.push(\"59\");i.push(\"13\");i.push(\"10\");i.push(\"118\");i.push(\"97\");i.push(\"" ascii
    $s19 = ";}} return ZSsDqYHNzjy}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}