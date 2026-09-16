rule sig_20151217_e3f028bf17f5856bf3eba07a5afd0a98 {
  meta:
    description = "datamaliciousorder - file 20151217_e3f028bf17f5856bf3eba07a5afd0a98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270404fb32fbfda0ac6185fe6f52714a6643b6c3b0d8465bbf6b6b54c2501592"

  strings:
    $s1  = "th.pow(Math.cos(418), 2) - 1)); while(true) { if(WUvPBhXrf[kJjRHEBSbgr] > ExPzu[kJjRHEBSbgr].length-(419+234)/653) { break; } if" ascii
    $s2  = "function JKcFkQcbuAEwmyPPz(ExPzu){ioffoFLelhR= '';kJjRHEBSbgr=Math.round((Math.pow(Math.sin(565), 2) + Math.pow(Math.cos(565), 2" ascii
    $s3  = ") - 1));while(true){if (kJjRHEBSbgr >= (2821+587)/568){break;}WUvPBhXrf[kJjRHEBSbgr]=Math.round((Math.pow(Math.sin(418), 2) + Ma" ascii
    $s4  = "ow(Math.cos(58), 2) - 1)));} WUvPBhXrf[kJjRHEBSbgr]++;}kJjRHEBSbgr++;} return ioffoFLelhR}" fullword ascii
    $s5  = "function JKcFkQcbuAEwmyPPz(ExPzu){ioffoFLelhR= '';kJjRHEBSbgr=Math.round((Math.pow(Math.sin(565), 2) + Math.pow(Math.cos(565), 2" ascii
    $s6  = "function VUDHBqE(RMnbwRXdjtKQOryOXBJwEeVLzPEsnhLqWDpB) {return !AdJSPLUqVDv(SlTlyQUpHrBFsKx(RMnbwRXdjtKQOryOXBJwEeVLzPEsnhLqWDpB" ascii
    $s7  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s8  = "function QXJuoBDyQTXGtLj(qVpCKQxSBPjgDMFpP,EnfIPpgKDnmKXhMCezShZrBrWvAKJGjkLj,YloEZWsnIZsbshZbUVkUHTAHAgCbFBQXqmI){eval(qVpCKQxS" ascii
    $s9  = "function QXJuoBDyQTXGtLj(qVpCKQxSBPjgDMFpP,EnfIPpgKDnmKXhMCezShZrBrWvAKJGjkLj,YloEZWsnIZsbshZbUVkUHTAHAgCbFBQXqmI){eval(qVpCKQxS" ascii
    $s10 = "i);return ldUdE;}" fullword ascii
    $s11 = "function OSpMVzkNHaoLituTNFkQfjCxjRqFFHHMgdMvjUXKziJEceHveHdnXH(nQJIlTKpoofVU,NUMYBjBPFDRayR){ return fChPghE[mXJaQXnN[qYNJb(nQJ" ascii
    $s12 = "function AdJSPLUqVDv(wMVEgaELtbrtzH) {return isNaN(wMVEgaELtbrtzH);}" fullword ascii
    $s13 = "function VUDHBqE(RMnbwRXdjtKQOryOXBJwEeVLzPEsnhLqWDpB) {return !AdJSPLUqVDv(SlTlyQUpHrBFsKx(RMnbwRXdjtKQOryOXBJwEeVLzPEsnhLqWDpB" ascii
    $s14 = "function OSpMVzkNHaoLituTNFkQfjCxjRqFFHHMgdMvjUXKziJEceHveHdnXH(nQJIlTKpoofVU,NUMYBjBPFDRayR){ return fChPghE[mXJaQXnN[qYNJb(nQJ" ascii
    $s15 = "function SlTlyQUpHrBFsKx(TICXzSyoqbIHTEHCozr) {return parseFloat(TICXzSyoqbIHTEHCozr);}" fullword ascii
    $s16 = "function swbwUYZQVuaK(gfORPwOTMTjZm) {return isFinite(gfORPwOTMTjZm);}" fullword ascii
    $s17 = "function b(cdyFLkdbKWvgNH,zIdQwqzrHJAjc,BxNtGogISDx) {cdyFLkdbKWvgNH[zIdQwqzrHJAjc]=BxNtGogISDx;}" fullword ascii
    $s18 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s19 = "function R(iPRQfwyaBNPr,bUPCVzpJoyyIFm){iPRQfwyaBNPr.push(bUPCVzpJoyyIFm);}" fullword ascii
    $s20 = "function iTnveMgvFJCyJuIef(zKcbrrOByJ,gWuoMjDCvj) {return parseInt(zKcbrrOByJ,gWuoMjDCvj);}" fullword ascii

  condition:
    uint16(0) == 0x586d and
    8 of them
}