rule sig_20151216_dd94f41f647059fd3b69e0d70feaabca {
  meta:
    description = "datamaliciousorder - file 20151216_dd94f41f647059fd3b69e0d70feaabca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99329df9a3b97bc36b247367ce732c2300b3981e841f5a86c5ef6eb35f020c07"

  strings:
    $s1  = "Math.cos(509), 2) - 1)));} dvaPyJEZR[hDAkDCaesBK]++;}hDAkDCaesBK++;} return JlHodYkEjwf}" fullword ascii
    $s2  = "function hfdDLCqfWhgzlNfCt(UezNV){JlHodYkEjwf= '';hDAkDCaesBK=Math.round((Math.pow(Math.sin(552), 2) + Math.pow(Math.cos(552), 2" ascii
    $s3  = ") - 1));while(true){if (hDAkDCaesBK >= (5027+805)/972){break;}dvaPyJEZR[hDAkDCaesBK]=Math.round((Math.pow(Math.sin(458), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(458), 2) - 1)); while(true) { if(dvaPyJEZR[hDAkDCaesBK] > UezNV[hDAkDCaesBK].length-(301+667)/968) { break; } if" ascii
    $s5  = "function hfdDLCqfWhgzlNfCt(UezNV){JlHodYkEjwf= '';hDAkDCaesBK=Math.round((Math.pow(Math.sin(552), 2) + Math.pow(Math.cos(552), 2" ascii
    $s6  = "function JVOgalo(sDIyLKVrSqtHqfAjDPUokRBHJUoqGAuzrIOL) {return !FyQQVxsIRux(KSHqRCFAPBbnlFB(sDIyLKVrSqtHqfAjDPUokRBHJUoqGAuzrIOL" ascii
    $s7  = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s8  = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s9  = "function FyQQVxsIRux(mJmoPQdbeSIhTE) {return isNaN(mJmoPQdbeSIhTE);}" fullword ascii
    $s10 = "function Gbxri(MPWMTFpPPVH,WrVLwBjPFzKNX,qtgKFslB){oxah=TgGkjSKveYzNAGPBy(MPWMTFpPPVH,WrVLwBjPFzKNX);zdAkL=oxah.toString(qtgKFsl" ascii
    $s11 = "function TgGkjSKveYzNAGPBy(OHgayvZgUR,idVVcRNDjO) {return parseInt(OHgayvZgUR,idVVcRNDjO);}" fullword ascii
    $s12 = "function FEksSuQdTvYRiBx(xmxGRzggJzkyHYRQL,YfNhFckPBWeXlyuWWdwYyCTZHIyoSEuxTF,HkqTFdUVzYMdHdLCnGWyVsWhbvbuOtzcvco){eval(xmxGRzgg" ascii
    $s13 = "function vCYcYBDzihAk(UQPrIOjaBSJoJ) {return isFinite(UQPrIOjaBSJoJ);}" fullword ascii
    $s14 = "function FEksSuQdTvYRiBx(xmxGRzggJzkyHYRQL,YfNhFckPBWeXlyuWWdwYyCTZHIyoSEuxTF,HkqTFdUVzYMdHdLCnGWyVsWhbvbuOtzcvco){eval(xmxGRzgg" ascii
    $s15 = "function XFDLZHdzDroDYuraZRzXxRDvfddMkXGpYrZnkqZfMJWyzbiJBJEVFg(wbUDYLZEYZHsc,ApKzqaVcPQVUuw){ return mVDtuHQ[WvaCfjPa[Gbxri(wbU" ascii
    $s16 = "function JVOgalo(sDIyLKVrSqtHqfAjDPUokRBHJUoqGAuzrIOL) {return !FyQQVxsIRux(KSHqRCFAPBbnlFB(sDIyLKVrSqtHqfAjDPUokRBHJUoqGAuzrIOL" ascii
    $s17 = "function Gbxri(MPWMTFpPPVH,WrVLwBjPFzKNX,qtgKFslB){oxah=TgGkjSKveYzNAGPBy(MPWMTFpPPVH,WrVLwBjPFzKNX);zdAkL=oxah.toString(qtgKFsl" ascii
    $s18 = "function KSHqRCFAPBbnlFB(NDXrTJExPBNJjXbiAah) {return parseFloat(NDXrTJExPBNJjXbiAah);}" fullword ascii
    $s19 = "function XFDLZHdzDroDYuraZRzXxRDvfddMkXGpYrZnkqZfMJWyzbiJBJEVFg(wbUDYLZEYZHsc,ApKzqaVcPQVUuw){ return mVDtuHQ[WvaCfjPa[Gbxri(wbU" ascii
    $s20 = "function U(NOGlVJhBWyuSBJ,kApVYtFEeautV,uMnpduSJPwF) {NOGlVJhBWyuSBJ[kApVYtFEeautV]=uMnpduSJPwF;}" fullword ascii

  condition:
    uint16(0) == 0x7657 and
    8 of them
}