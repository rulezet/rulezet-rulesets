rule sig_20151217_0b5d8255066e9f6b02de977068500aa7 {
  meta:
    description = "datamaliciousorder - file 20151217_0b5d8255066e9f6b02de977068500aa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c69e09702f7ae71de7cc32e2c6905f0233ebe75ed044821ef57ba5778a89cac1"

  strings:
    $s1  = "function YWUbyYQCEuwfPagbH(Wudbm){IPWkKuqpeYQ= '';nIPCxsEwuxd=Math.round((Math.pow(Math.sin(39), 2) + Math.pow(Math.cos(39), 2) " ascii
    $s2  = "ow(Math.cos(357), 2) - 1)));} Exktherte[nIPCxsEwuxd]++;}nIPCxsEwuxd++;} return IPWkKuqpeYQ}" fullword ascii
    $s3  = ".pow(Math.cos(602), 2) - 1)); while(true) { if(Exktherte[nIPCxsEwuxd] > Wudbm[nIPCxsEwuxd].length-(-175+983)/808) { break; } if " ascii
    $s4  = "function YWUbyYQCEuwfPagbH(Wudbm){IPWkKuqpeYQ= '';nIPCxsEwuxd=Math.round((Math.pow(Math.sin(39), 2) + Math.pow(Math.cos(39), 2) " ascii
    $s5  = "- 1));while(true){if (nIPCxsEwuxd >= (5170+146)/886){break;}Exktherte[nIPCxsEwuxd]=Math.round((Math.pow(Math.sin(602), 2) + Math" ascii
    $s6  = "function ckpzdkM(glwwxadyrmrDXgTWDbUIUOPxqLQyBXJlDEtR) {return !SsXhXWcGZYi(OcJyjKjMjmFANzn(glwwxadyrmrDXgTWDbUIUOPxqLQyBXJlDEtR" ascii
    $s7  = "function SsXhXWcGZYi(poPjTphKcBSVVB) {return isNaN(poPjTphKcBSVVB);}" fullword ascii
    $s8  = "function BVoNHLXvGRvfhnZQpahqhmhvGvsYZTSuILPrmxCqxAOMmPByuzpvvd(uVWOTHtvVkkyf,ZEqNxEtAYVQMMZ){ return aVddBrp[AYcOaYsi[ZeBHM(uVW" ascii
    $s9  = "function nBQgtyTCQpmXlct(RNIJfertfefshDpvo,UJPYBoYGlrGhxLKjKbwejOmZqIIvASjFzd,yQIMkjqxzseNHxWYqPkdwdkydcOOqJbAYcb){eval(RNIJfert" ascii
    $s10 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s11 = "function CrEmAzFKEFZM(FFHkIDLbqbvpX) {return isFinite(FFHkIDLbqbvpX);}" fullword ascii
    $s12 = "function o(MosSbsvQqJan,ZpPhJGpbbkpmtt){MosSbsvQqJan.push(ZpPhJGpbbkpmtt);}" fullword ascii
    $s13 = "function Q(IDGOIDRhFxZwVG,GOJOYJxBanPdX,WExWCQWuXSU) {IDGOIDRhFxZwVG[GOJOYJxBanPdX]=WExWCQWuXSU;}" fullword ascii
    $s14 = "function BVoNHLXvGRvfhnZQpahqhmhvGvsYZTSuILPrmxCqxAOMmPByuzpvvd(uVWOTHtvVkkyf,ZEqNxEtAYVQMMZ){ return aVddBrp[AYcOaYsi[ZeBHM(uVW" ascii
    $s15 = "function ZeBHM(yWbeGqrbHBM,zVobtQfPHiXIp,wjgOnMFt){hcKC=gWuktYJQYIMgXiRPV(yWbeGqrbHBM,zVobtQfPHiXIp);qdQdd=hcKC.toString(wjgOnMF" ascii
    $s16 = "function gWuktYJQYIMgXiRPV(HRCSdJodwn,YIhCPmcJgv) {return parseInt(HRCSdJodwn,YIhCPmcJgv);}" fullword ascii
    $s17 = "function nBQgtyTCQpmXlct(RNIJfertfefshDpvo,UJPYBoYGlrGhxLKjKbwejOmZqIIvASjFzd,yQIMkjqxzseNHxWYqPkdwdkydcOOqJbAYcb){eval(RNIJfert" ascii
    $s18 = "function ZeBHM(yWbeGqrbHBM,zVobtQfPHiXIp,wjgOnMFt){hcKC=gWuktYJQYIMgXiRPV(yWbeGqrbHBM,zVobtQfPHiXIp);qdQdd=hcKC.toString(wjgOnMF" ascii
    $s19 = "function OcJyjKjMjmFANzn(pNFpQCUWWxosoROGgGU) {return parseFloat(pNFpQCUWWxosoROGgGU);}" fullword ascii
    $s20 = "function ckpzdkM(glwwxadyrmrDXgTWDbUIUOPxqLQyBXJlDEtR) {return !SsXhXWcGZYi(OcJyjKjMjmFANzn(glwwxadyrmrDXgTWDbUIUOPxqLQyBXJlDEtR" ascii

  condition:
    uint16(0) == 0x5941 and
    8 of them
}