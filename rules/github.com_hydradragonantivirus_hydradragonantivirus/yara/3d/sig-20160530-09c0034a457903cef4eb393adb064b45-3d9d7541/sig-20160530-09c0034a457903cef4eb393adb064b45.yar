rule sig_20160530_09c0034a457903cef4eb393adb064b45 {
  meta:
    description = "datamaliciousorder - file 20160530_09c0034a457903cef4eb393adb064b45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fbf97af70592819fca6cd2a936c4c75368ba247372626ece5f3da0c3f02f2f8"

  strings:
    $s1  = "var QWGndSFPmAlY=function(){return WScript.CreateObject(AVNpKngaTlqzZGqCgVALFjP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function MpwWBtbj(npoIfRieU,zhUwOQgEahAzfEScVPzi){return npoIfRieU.charAt(zhUwOQgEahAzfEScVPzi);}" fullword ascii
    $s3  = "function Ai(WNsfTcxOaIPXpFdGm){return String.fromCharCode(WNsfTcxOaIPXpFdGm);}" fullword ascii
    $s4  = "function dRMQsmJzTFBm(){return QWGndSFPmAlY.ExpandEnvironmentStrings(vPmwX())}" fullword ascii
    $s5  = "function HdzZTYtXdiZB(RLPxkZyzicuNx) {var GxIHTDybebdqplOi = MPvlmWdsJRsRVmEpTkTyPs.join(AVNpKngaTlqzZGqCgVALFjP[7]);var XikTytw" ascii
    $s6  = "function rtVFk(){return gbDNiLalG(AVNpKngaTlqzZGqCgVALFjP[13],[0,3,6],AVNpKngaTlqzZGqCgVALFjP[14]);}" fullword ascii
    $s7  = "function chQMKuHeeTWjKs(){return gbDNiLalG(AVNpKngaTlqzZGqCgVALFjP[11],[2,4,8,10],AVNpKngaTlqzZGqCgVALFjP[12]);}" fullword ascii
    $s8  = "function HdzZTYtXdiZB(RLPxkZyzicuNx) {var GxIHTDybebdqplOi = MPvlmWdsJRsRVmEpTkTyPs.join(AVNpKngaTlqzZGqCgVALFjP[7]);var XikTytw" ascii
    $s9  = "function uhjzG(HCBzZFlfnfIQ,wGLfI) {var GMHTwObkDDRI=[AVNpKngaTlqzZGqCgVALFjP[15]];HCBzZFlfnfIQ[GMHTwObkDDRI[0]]" fullword ascii
    $s10 = "ILLJDe += gKElPtlInyd(XikTytwNNxmWqrPfdGs, NkVlygLEVeNWR, KmqEMtwsA);} while (jlmGzdPvFTNGOhnIIpCZUAt < RLPxkZyzicuNx.length);re" ascii
    $s11 = "twNNxmWqrPfdGs);else if (phbhjje == 64) pIgQbJDCYGDILLJDe += QwlSQUimrKbwef(XikTytwNNxmWqrPfdGs, NkVlygLEVeNWR);else pIgQbJDCYGD" ascii
    $s12 = "function gbDNiLalG(sQBng,MCwzWWraQ,stxiVNW){vWsTyEZLBhA=sQBng.split(stxiVNW);MVgHgZLyfLyg = AVNpKngaTlqzZGqCgVALFjP[0];for(hXPxC" ascii
    $s13 = "function JkZvAnOFv(KeZQJnO,GSZvmgZuTZcj){return KeZQJnO.indexOf(GSZvmgZuTZcj);}" fullword ascii
    $s14 = "function vPmwX(){return gbDNiLalG(AVNpKngaTlqzZGqCgVALFjP[9],[1,5,7],AVNpKngaTlqzZGqCgVALFjP[10]);}" fullword ascii
    $s15 = "function QwlSQUimrKbwef(zCZTmZCxiQPKas,KbOfKFpmm){return String.fromCharCode(zCZTmZCxiQPKas,KbOfKFpmm);}" fullword ascii
    $s16 = "var tLlIVzbGUfVyu = PLtYnnJuHUF.createtextfile(QWGndSFPmAlY.ExpandEnvironmentStrings(AVNpKngaTlqzZGqCgVALFjP[3]+AVNpKngaTlqzZGqC" ascii
    $s17 = "function gbDNiLalG(sQBng,MCwzWWraQ,stxiVNW){vWsTyEZLBhA=sQBng.split(stxiVNW);MVgHgZLyfLyg = AVNpKngaTlqzZGqCgVALFjP[0];for(hXPxC" ascii
    $s18 = "function gKElPtlInyd(TnhyJomUTmaIQHemv,YBHqUQDZWqrEAACB,qPXPvfcTGKpxjdoCOERzBZ){return String.fromCharCode(TnhyJomUTmaIQHemv,YBH" ascii
    $s19 = "EykFredC=0;hXPxCEykFredC<MCwzWWraQ.length;hXPxCEykFredC++) {MVgHgZLyfLyg+=vWsTyEZLBhA[MCwzWWraQ[hXPxCEykFredC]];}return MVgHgZLy" ascii
    $s20 = "gVALFjP[4])+String.fromCharCode(92)+AVNpKngaTlqzZGqCgVALFjP[5],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}