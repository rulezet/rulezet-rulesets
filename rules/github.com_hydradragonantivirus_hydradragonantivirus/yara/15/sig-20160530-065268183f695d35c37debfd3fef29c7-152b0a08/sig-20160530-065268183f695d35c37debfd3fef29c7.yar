rule sig_20160530_065268183f695d35c37debfd3fef29c7 {
  meta:
    description = "datamaliciousorder - file 20160530_065268183f695d35c37debfd3fef29c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b012a20ccad1afa3b81305f6f4503e419b35eedde274b0090c689ea81acd3ce"

  strings:
    $s1  = "var LVrXxmR=function(){return WScript.CreateObject(QkpIulEOy[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function VYWaJNMmUouw(gWoKhGWhLjG,GgsyqDXfOwwvsdUbx){return gWoKhGWhLjG.charAt(GgsyqDXfOwwvsdUbx);}" fullword ascii
    $s3  = "function FAFxFxgFlNay(NgEhXHgg,runTeWk,lmsUaZgRpqJsfe){KmQWcZ=NgEhXHgg.split(lmsUaZgRpqJsfe);dlAGQHuFkHN = QkpIulEOy[0];for(fzxr" ascii
    $s4  = "VBYcUq=0;fzxrVBYcUq<runTeWk.length;fzxrVBYcUq++) {dlAGQHuFkHN+=KmQWcZ[runTeWk[fzxrVBYcUq]];}return dlAGQHuFkHN.substring(3,dlAGQ" ascii
    $s5  = "RHY.length);return GcDEn;}" fullword ascii
    $s6  = "function FAFxFxgFlNay(NgEhXHgg,runTeWk,lmsUaZgRpqJsfe){KmQWcZ=NgEhXHgg.split(lmsUaZgRpqJsfe);dlAGQHuFkHN = QkpIulEOy[0];for(fzxr" ascii
    $s7  = "function vkoPLvfBxUD(){return LVrXxmR.ExpandEnvironmentStrings(HLaYxA())}" fullword ascii
    $s8  = "function FcIpPz(GjyMicilusRHY) {var NAWpPHxS = jAvnp.join(QkpIulEOy[7]);var UsDpAte, nrORxDrPlZDIfaO, EyRodDzuaaPC, nPeERonqscNn" ascii
    $s9  = "te, nrORxDrPlZDIfaO);else GcDEn += vihywaJhxKlsshQTfDyrwzgb(UsDpAte, nrORxDrPlZDIfaO, EyRodDzuaaPC);} while (CgwiVb < GjyMicilus" ascii
    $s10 = "var rsOqCKzZiRB=function(){return new ActiveXObject(QkpIulEOy[1]);}();" fullword ascii
    $s11 = "var RwzKnsoGInmn = rsOqCKzZiRB.createtextfile(LVrXxmR.ExpandEnvironmentStrings(QkpIulEOy[3]+QkpIulEOy[4])+String.fromCharCode(92" ascii
    $s12 = "function UBPvlEYDTNFCSXNmEQrXHsW(DVmCDDWpQPZVkpUo,AbdNLAo){return DVmCDDWpQPZVkpUo.indexOf(AbdNLAo);}" fullword ascii
    $s13 = "function vihywaJhxKlsshQTfDyrwzgb(VkYQnso,EehTSZoGrWHL,jmTxAWWdLP){return String.fromCharCode(VkYQnso,EehTSZoGrWHL,jmTxAWWdLP);}" ascii
    $s14 = "function aYVZmaOQWsrB(GQrmYhMrKB,otFmOUpoWidzkEAS){return String.fromCharCode(GQrmYhMrKB,otFmOUpoWidzkEAS);}" fullword ascii
    $s15 = "function FcIpPz(GjyMicilusRHY) {var NAWpPHxS = jAvnp.join(QkpIulEOy[7]);var UsDpAte, nrORxDrPlZDIfaO, EyRodDzuaaPC, nPeERonqscNn" ascii
    $s16 = "function sHZqYVP(){return FAFxFxgFlNay(QkpIulEOy[11],[2,4,8,10],QkpIulEOy[12]);}" fullword ascii
    $s17 = "function HLaYxA(){return FAFxFxgFlNay(QkpIulEOy[9],[1,5,7],QkpIulEOy[10]);}" fullword ascii
    $s18 = "function MvhMfqCbX(JzPgCCYiILAS,SFaYLOnrX) {var MjrPxeGazfCz=[QkpIulEOy[15]];JzPgCCYiILAS[MjrPxeGazfCz[0]]" fullword ascii
    $s19 = ")+QkpIulEOy[5],true);" fullword ascii
    $s20 = "PC = TJjawxOAafikqfgbqQazuo & 0xff;if (mxVDZcLs == 64) GcDEn += qX(UsDpAte);else if (PkvOZSmD == 64) GcDEn += aYVZmaOQWsrB(UsDpA" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}