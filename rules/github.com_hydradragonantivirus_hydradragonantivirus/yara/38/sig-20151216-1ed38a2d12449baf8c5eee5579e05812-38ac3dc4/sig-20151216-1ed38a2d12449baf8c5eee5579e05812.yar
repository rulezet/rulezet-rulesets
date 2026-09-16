rule sig_20151216_1ed38a2d12449baf8c5eee5579e05812 {
  meta:
    description = "datamaliciousorder - file 20151216_1ed38a2d12449baf8c5eee5579e05812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b881b707ed7199a0a0f5ca3f1c47b408e2df38afb6bb9e93ba1b1caeaef7c5aa"

  strings:
    $s1  = "th.pow(Math.cos(934), 2) - 1)); while(true) { if(LwdFvhVRi[djLpjJzpCDX] > dvowS[djLpjJzpCDX].length-(-241+272)/31) { break; } if" ascii
    $s2  = "function hZrlemLUZQQZeVmSF(dvowS){ExcNhHoVNrV= '';djLpjJzpCDX=Math.round((Math.pow(Math.sin(211), 2) + Math.pow(Math.cos(211), 2" ascii
    $s3  = "pow(Math.cos(798), 2) - 1)));} LwdFvhVRi[djLpjJzpCDX]++;}djLpjJzpCDX++;} return ExcNhHoVNrV}" fullword ascii
    $s4  = ") - 1));while(true){if (djLpjJzpCDX >= (2233+983)/536){break;}LwdFvhVRi[djLpjJzpCDX]=Math.round((Math.pow(Math.sin(934), 2) + Ma" ascii
    $s5  = "function hZrlemLUZQQZeVmSF(dvowS){ExcNhHoVNrV= '';djLpjJzpCDX=Math.round((Math.pow(Math.sin(211), 2) + Math.pow(Math.cos(211), 2" ascii
    $s6  = "pyRpvqoDfjUjgunfRWyZPdxgyGEusxIFUMc([dvowS[djLpjJzpCDX][LwdFvhVRi[djLpjJzpCDX]]], Math.round((Math.pow(Math.sin(798), 2) + Math." ascii
    $s7  = "function lCZVVOM(nSQMHBvQKJJYJDHxdxYlnlprbHlnbximfvJo) {return !iVkMkpDxpNG(vYkgTaeKSRIHJhC(nSQMHBvQKJJYJDHxdxYlnlprbHlnbximfvJo" ascii
    $s8  = "function LdrrG(mZaNvNlPBJv,IsfBhGGNPKGrc,jVblpFts){qQTo=EvYNmoVmknvqQidcb(mZaNvNlPBJv,IsfBhGGNPKGrc);KhaIA=qQTo.toString(jVblpFt" ascii
    $s9  = "function fZlMPtVbNmvdpnj(pGMfAKXxTaRUjdADA,ZAVDpTKEqhyUYKSUUZhlugthlHGIISAWgt,yGGmqmRklTqnAFrmVBHmaoTAQpLFRfwbRjz){eval(pGMfAKXx" ascii
    $s10 = "function f(tYmmASNXLoWvwv,pMKbShDwJPQXZ,panfFSowjxX) {tYmmASNXLoWvwv[pMKbShDwJPQXZ]=panfFSowjxX;}" fullword ascii
    $s11 = "function cPOVQSytnAjzLXGccgupyRpvqoDfjUjgunfRWyZPdxgyGEusxIFUMc(vWSjcWuEKpZYc,UhNOPlVTCoBgpD){ return AEtdUjo[mDOZvLHG[LdrrG(vWS" ascii
    $s12 = "function lCZVVOM(nSQMHBvQKJJYJDHxdxYlnlprbHlnbximfvJo) {return !iVkMkpDxpNG(vYkgTaeKSRIHJhC(nSQMHBvQKJJYJDHxdxYlnlprbHlnbximfvJo" ascii
    $s13 = "function w(SZcjrkzjBAmm,ZJumGcJLYlVQMM){SZcjrkzjBAmm.push(ZJumGcJLYlVQMM);}" fullword ascii
    $s14 = "function cPOVQSytnAjzLXGccgupyRpvqoDfjUjgunfRWyZPdxgyGEusxIFUMc(vWSjcWuEKpZYc,UhNOPlVTCoBgpD){ return AEtdUjo[mDOZvLHG[LdrrG(vWS" ascii
    $s15 = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s16 = "function EvYNmoVmknvqQidcb(XoZwSIFxCc,uFVYUdWZtm) {return parseInt(XoZwSIFxCc,uFVYUdWZtm);}" fullword ascii
    $s17 = "function iVkMkpDxpNG(zkXIimONKwHGgA) {return isNaN(zkXIimONKwHGgA);}" fullword ascii
    $s18 = "function LdrrG(mZaNvNlPBJv,IsfBhGGNPKGrc,jVblpFts){qQTo=EvYNmoVmknvqQidcb(mZaNvNlPBJv,IsfBhGGNPKGrc);KhaIA=qQTo.toString(jVblpFt" ascii
    $s19 = "function vYkgTaeKSRIHJhC(yPYdveChShfsvAFttss) {return parseFloat(yPYdveChShfsvAFttss);}" fullword ascii
    $s20 = "function fZlMPtVbNmvdpnj(pGMfAKXxTaRUjdADA,ZAVDpTKEqhyUYKSUUZhlugthlHGIISAWgt,yGGmqmRklTqnAFrmVBHmaoTAQpLFRfwbRjz){eval(pGMfAKXx" ascii

  condition:
    uint16(0) == 0x446d and
    8 of them
}