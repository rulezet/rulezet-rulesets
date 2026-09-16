rule sig_20160530_5ab159aebeff775bf47200e9a7385a75 {
  meta:
    description = "datamaliciousorder - file 20160530_5ab159aebeff775bf47200e9a7385a75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f857a51befc6e72908cdf51db69d706d1b2d07ee9b9ee8e9feb4a8440a2998f4"

  strings:
    $s1  = "var JjlvmLdpCkg=function(){return WScript.CreateObject(MwMdQboOllcGHyEqvHaL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "tring.fromCharCode(92)+MwMdQboOllcGHyEqvHaL[5],true);" fullword ascii
    $s3  = "function CapgWCFU(bhKCfldBIvLmfkHIl,OdtkIYljTMIJ){return bhKCfldBIvLmfkHIl.charAt(OdtkIYljTMIJ);}" fullword ascii
    $s4  = "function qgnnHwxEocihWyJzHeqAeMzo(KLwOGrzgaevbachvnZIWrx,qOFpkLrPmnwMKEMLzmf,QjuynYOKNyU){return String.fromCharCode(KLwOGrzgaev" ascii
    $s5  = "function BdG(SaZuX){return String.fromCharCode(SaZuX);}" fullword ascii
    $s6  = "function mPQcmKtVQ(zVJjgBQBd,kuXNAd) {var EJJBsVUWxLlG=[MwMdQboOllcGHyEqvHaL[15]];zVJjgBQBd[EJJBsVUWxLlG[0]]" fullword ascii
    $s7  = "function kUilDnbcDAu(gvMFQFgxc,bMSXGgzQYtuYF,NRheAirlGg){jburJjnDCSOX=gvMFQFgxc.split(NRheAirlGg);ChzKAXUOY = MwMdQboOllcGHyEqvH" ascii
    $s8  = "function iQMUP(EZmaSlfT,xdJYGkCK){return String.fromCharCode(EZmaSlfT,xdJYGkCK);}" fullword ascii
    $s9  = "function wJzuUVHHvtawMbApIJMon(svNWBhBPubtSTI,mJfdNMmGcvhXsGsKj){return svNWBhBPubtSTI.indexOf(mJfdNMmGcvhXsGsKj);}" fullword ascii
    $s10 = "function CIPjgVdTN(){return JjlvmLdpCkg.ExpandEnvironmentStrings(llFBpvsCZktR())}" fullword ascii
    $s11 = "function ZIKaLw(){return kUilDnbcDAu(MwMdQboOllcGHyEqvHaL[11],[2,4,8,10],MwMdQboOllcGHyEqvHaL[12]);}" fullword ascii
    $s12 = "function llFBpvsCZktR(){return kUilDnbcDAu(MwMdQboOllcGHyEqvHaL[9],[1,5,7],MwMdQboOllcGHyEqvHaL[10]);}" fullword ascii
    $s13 = "bOJPKbLYJKWkfn == 64) OLSGVtZAckNZqQCVdD += iQMUP(iaDlPxauCdSg, ThkSMsjzxsliNn);else OLSGVtZAckNZqQCVdD += qgnnHwxEocihWyJzHeqAe" ascii
    $s14 = "function kUilDnbcDAu(gvMFQFgxc,bMSXGgzQYtuYF,NRheAirlGg){jburJjnDCSOX=gvMFQFgxc.split(NRheAirlGg);ChzKAXUOY = MwMdQboOllcGHyEqvH" ascii
    $s15 = "var RliUdw = JcxxUPHbJYSz.createtextfile(JjlvmLdpCkg.ExpandEnvironmentStrings(MwMdQboOllcGHyEqvHaL[3]+MwMdQboOllcGHyEqvHaL[4])+S" ascii
    $s16 = "aL[0];for(oIOdThUefB=0;oIOdThUefB<bMSXGgzQYtuYF.length;oIOdThUefB++) {ChzKAXUOY+=jburJjnDCSOX[bMSXGgzQYtuYF[oIOdThUefB]];}return" ascii
    $s17 = "Mzo(iaDlPxauCdSg, ThkSMsjzxsliNn, ABeJuppupeeXnSBBwax);} while (wLocgxefJKqWSghK < jHgVAEOiogHYg.length);return OLSGVtZAckNZqQCV" ascii
    $s18 = "RXyA>> 8 & 0xff;ABeJuppupeeXnSBBwax = zGtHHRXyA & 0xff;if (PoVYgPYnyA == 64) OLSGVtZAckNZqQCVdD += BdG(iaDlPxauCdSg);else if (qY" ascii
    $s19 = "function qgnnHwxEocihWyJzHeqAeMzo(KLwOGrzgaevbachvnZIWrx,qOFpkLrPmnwMKEMLzmf,QjuynYOKNyU){return String.fromCharCode(KLwOGrzgaev" ascii
    $s20 = "function AdqikVTMW(){return kUilDnbcDAu(MwMdQboOllcGHyEqvHaL[13],[0,3,6],MwMdQboOllcGHyEqvHaL[14]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}