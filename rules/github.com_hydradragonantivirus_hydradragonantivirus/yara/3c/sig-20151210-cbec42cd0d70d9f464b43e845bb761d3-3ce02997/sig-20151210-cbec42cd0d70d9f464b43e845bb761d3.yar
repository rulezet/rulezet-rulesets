rule sig_20151210_cbec42cd0d70d9f464b43e845bb761d3 {
  meta:
    description = "datamaliciousorder - file 20151210_cbec42cd0d70d9f464b43e845bb761d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "628c90656b3c4c4032fbf93f5d3655403ee03c453f30f050e467a6a98e5806dd"

  strings:
    $s1  = "function tJjXrGa(egIMcHffbrqIHmfJbYSQAiTnUgleGVbFzsFv) {return !isNaN(parseFloat(egIMcHffbrqIHmfJbYSQAiTnUgleGVbFzsFv)) && isFin" ascii
    $s2  = "function tJjXrGa(egIMcHffbrqIHmfJbYSQAiTnUgleGVbFzsFv) {return !isNaN(parseFloat(egIMcHffbrqIHmfJbYSQAiTnUgleGVbFzsFv)) && isFin" ascii
    $s3  = "RyEuYys=(-334+334)/680;while(true){if(RyEuYys>=(39755+181)/312){break;}eCtSGRkRsvnrV[RyEuYys]=String.fromCharCode(RyEuYys);RyEuY" ascii
    $s4  = "+;}} return iTYHHymXyQm}" fullword ascii
    $s5  = "function aCbBCzQKbCiMzgoeAOaCyeSNHSsGXpMXiLGuHdxncBITNbxlIWgGVe(xOjZkszLABjzd,NUIdjokvqXrWta){ return eCtSGRkRsvnrV[mwrWm(xOjZks" ascii
    $s6  = "function jMlyKsWWJrU(TBappHlq,dexwrd){return TBappHlq.split(dexwrd)}" fullword ascii
    $s7  = "function aCbBCzQKbCiMzgoeAOaCyeSNHSsGXpMXiLGuHdxncBITNbxlIWgGVe(xOjZkszLABjzd,NUIdjokvqXrWta){ return eCtSGRkRsvnrV[mwrWm(xOjZks" ascii
    $s8  = "RyEuYys=(-334+334)/680;while(true){if(RyEuYys>=(39755+181)/312){break;}eCtSGRkRsvnrV[RyEuYys]=String.fromCharCode(RyEuYys);RyEuY" ascii
    $s9  = " qydsD;}function aaFfkHFgiCjtxJi(uXjYBTBkoTltuQIVv){eval(uXjYBTBkoTltuQIVv)}" fullword ascii
    $s10 = "function mwrWm(SiMLwOaMleU,qFoZCxcjLZRjm,ccFpvYXV){WeTx=parseInt(SiMLwOaMleU,qFoZCxcjLZRjm);qydsD=WeTx.toString(ccFpvYXV);return" ascii
    $s11 = "function mwrWm(SiMLwOaMleU,qFoZCxcjLZRjm,ccFpvYXV){WeTx=parseInt(SiMLwOaMleU,qFoZCxcjLZRjm);qydsD=WeTx.toString(ccFpvYXV);return" ascii
    $s12 = "tysyAMgTi[bJtAPOfklOl]=(-537+537)/949; while(true) { if(tysyAMgTi[bJtAPOfklOl] > PPNCa[bJtAPOfklOl].length-(551+179)/730) { brea" ascii
    $s13 = "function UmyXFEDlJsDEtkXDQ(PPNCa){iTYHHymXyQm= '';for(bJtAPOfklOl=(-235+235)/752; bJtAPOfklOl < (1164+676)/920; bJtAPOfklOl++) {" ascii
    $s14 = "function UmyXFEDlJsDEtkXDQ(PPNCa){iTYHHymXyQm= '';for(bJtAPOfklOl=(-235+235)/752; bJtAPOfklOl < (1164+676)/920; bJtAPOfklOl++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}