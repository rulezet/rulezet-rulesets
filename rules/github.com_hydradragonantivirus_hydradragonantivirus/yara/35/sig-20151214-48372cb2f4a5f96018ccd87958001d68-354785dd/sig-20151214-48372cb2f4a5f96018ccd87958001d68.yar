rule sig_20151214_48372cb2f4a5f96018ccd87958001d68 {
  meta:
    description = "datamaliciousorder - file 20151214_48372cb2f4a5f96018ccd87958001d68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d95fee6ccb638f739de989bbdbb5ad0a16d5537062686d859c2620ea1478eb8"

  strings:
    $s1  = "Math.pow(Math.cos(816), 2) - 1)); while(true) { if(REmnFUqUn[kCBAnQLjDrY] > zNVrJ[kCBAnQLjDrY].length-(-258+525)/267) { break; }" ascii
    $s2  = "h.pow(Math.cos(96), 2) - 1)));} REmnFUqUn[kCBAnQLjDrY]++;}} return YYELYvejzjc}" fullword ascii
    $s3  = "function HpDDoGXusZdfyuCrb(zNVrJ){YYELYvejzjc= z[1804];for(kCBAnQLjDrY=Math.round((Math.pow(Math.sin(847), 2) + Math.pow(Math.co" ascii
    $s4  = "function HpDDoGXusZdfyuCrb(zNVrJ){YYELYvejzjc= z[1804];for(kCBAnQLjDrY=Math.round((Math.pow(Math.sin(847), 2) + Math.pow(Math.co" ascii
    $s5  = "function U(EYuyECKvJtNX,QZfeQgdEfWgmmT){EYuyECKvJtNX.push(QZfeQgdEfWgmmT);}function m8(bkSopvcsbBTmCBuP){if(FBknWqv(bkSopvcsbBTm" ascii
    $s6  = "CBuP)) {return (String.fromCharCode(bkSopvcsbBTmCBuP) + String.fromCharCode((30189+516)/445));}}" fullword ascii
    $s7  = "function ZcKYM(YzFntcWxfpb,zTKPLRpQwwBte,VSpPBWjH){lIyM=parseInt(YzFntcWxfpb,zTKPLRpQwwBte);gpJDG=lIyM.toString(VSpPBWjH);return" ascii
    $s8  = "function U(EYuyECKvJtNX,QZfeQgdEfWgmmT){EYuyECKvJtNX.push(QZfeQgdEfWgmmT);}function m8(bkSopvcsbBTmCBuP){if(FBknWqv(bkSopvcsbBTm" ascii
    $s9  = "function dGqxaDHyNCwKxvwuMuRcZMGnPzANNrHxEsfdLHISteLyNqXjMHHtZK(jGoeQkeXFXCGt,uzzNbUuyfVIHTh){ return zGsJUbp[GdESRzdT[ZcKYM(jGo" ascii
    $s10 = "function dGqxaDHyNCwKxvwuMuRcZMGnPzANNrHxEsfdLHISteLyNqXjMHHtZK(jGoeQkeXFXCGt,uzzNbUuyfVIHTh){ return zGsJUbp[GdESRzdT[ZcKYM(jGo" ascii
    $s11 = "function QvprzvaFKxTvBUW(IiSZxuynFLIxYZook){eval(IiSZxuynFLIxYZook)}" fullword ascii
    $s12 = "function ZcKYM(YzFntcWxfpb,zTKPLRpQwwBte,VSpPBWjH){lIyM=parseInt(YzFntcWxfpb,zTKPLRpQwwBte);gpJDG=lIyM.toString(VSpPBWjH);return" ascii
    $s13 = " gpJDG;}function QvprzvaFKxTvBUW(IiSZxuynFLIxYZook,UiStBWWXGIYnSMMLGSdiiUgJzwBSjJtOlC,lbVzjlNvvWgOabqjCVFUzNBtvaWHeAuFQQh){eval(" ascii
    $s14 = "var z=new Array();" fullword ascii
    $s15 = "function FBknWqv(FCebJuXHBSGxqRDPSTmuNMoRnXZbqGcaAsBb) {return !isNaN(parseFloat(FCebJuXHBSGxqRDPSTmuNMoRnXZbqGcaAsBb)) && isFin" ascii
    $s16 = "function FBknWqv(FCebJuXHBSGxqRDPSTmuNMoRnXZbqGcaAsBb) {return !isNaN(parseFloat(FCebJuXHBSGxqRDPSTmuNMoRnXZbqGcaAsBb)) && isFin" ascii
    $s17 = "function enCAiXljCPd(vxAdQDoz,LhjDvf){return vxAdQDoz.split(LhjDvf)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}