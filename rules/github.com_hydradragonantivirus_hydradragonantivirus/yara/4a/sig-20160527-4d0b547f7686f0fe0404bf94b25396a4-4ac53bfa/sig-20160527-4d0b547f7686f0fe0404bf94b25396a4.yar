rule sig_20160527_4d0b547f7686f0fe0404bf94b25396a4 {
  meta:
    description = "datamaliciousorder - file 20160527_4d0b547f7686f0fe0404bf94b25396a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cdf070543d2a7cc215918f46400bb2c3c483fe8ed81ccf2dd0693ba2fd3a3a2"

  strings:
    $s1  = "function uqdJvwBzqvNZ() {return WScript;}function RzydxRrooFmOe(){return fNAvqlAiXdR.ExpandEnvironmentStrings(bOgogk())}" fullword ascii
    $s2  = "function GFTvoQY(TAXdLWNzTFj,HSVdFWBtUQazpXuskhrkA){return TAXdLWNzTFj.charAt(HSVdFWBtUQazpXuskhrkA);}" fullword ascii
    $s3  = "push(\"U\");fdDRZrjwpavm.push(\"V\");fdDRZrjwpavm.push(\"W\");fdDRZrjwpavm.push(\"X\");fdDRZrjwpavm.push(\"Y\");fdDRZrjwpavm.pus" ascii
    $s4  = "function ZygsnbcngM(VNxOpPVPDzFYA) {var QSNDcwVczUmqopCX = fdDRZrjwpavm.join(ciSBxcTkGkjPLydsUQcD[6]);var JqCgynTtmCqajOmUp, pxZ" ascii
    $s5  = "var uHmvJSLnGDdp=function(){return new ActiveXObject(ciSBxcTkGkjPLydsUQcD[0]);}();" fullword ascii
    $s6  = "function OOfzQUqjnROJ(dJHXUjbfAmJt,bChytEj) {var hMybXBQHpCf=[ciSBxcTkGkjPLydsUQcD[15]];dJHXUjbfAmJt[hMybXBQHpCf[0]](bChytEj,0x1" ascii
    $s7  = "function WcJLrSOZ(){return pkkPjEmxU(ciSBxcTkGkjPLydsUQcD[12],[0,3,6],ciSBxcTkGkjPLydsUQcD[13]);}" fullword ascii
    $s8  = "function z(UzfehdJexyTATB){return String.fromCharCode(UzfehdJexyTATB);}" fullword ascii
    $s9  = "var fNAvqlAiXdR=function(){return uqdJvwBzqvNZ().CreateObject(ciSBxcTkGkjPLydsUQcD[1].replace(new RegExp(\"u\",\"g\"),\"\"));}()" ascii
    $s10 = "(JqCgynTtmCqajOmUp);else if (sxAuljGbgofrU == 64) epNHCIpwjQNtJaIUCyEaZe += HqpJf(JqCgynTtmCqajOmUp, pxZHGKxogjKw);else epNHCIpw" ascii
    $s11 = "function pkkPjEmxU(OOjRynN,PgdsOV,selkaMxBqpNAA){GbqSEyiKuQbC=OOjRynN.split(selkaMxBqpNAA);qOeepyGQhHNvd = ciSBxcTkGkjPLydsUQcD[" ascii
    $s12 = "+String.fromCharCode(92)+ciSBxcTkGkjPLydsUQcD[4],true);" fullword ascii
    $s13 = "function OOfzQUqjnROJ(dJHXUjbfAmJt,bChytEj) {var hMybXBQHpCf=[ciSBxcTkGkjPLydsUQcD[15]];dJHXUjbfAmJt[hMybXBQHpCf[0]](bChytEj,0x1" ascii
    $s14 = "14];for(UGwwJ=0;UGwwJ<PgdsOV.length;UGwwJ++) {qOeepyGQhHNvd+=GbqSEyiKuQbC[PgdsOV[UGwwJ]];}return qOeepyGQhHNvd.substring(3,qOeep" ascii
    $s15 = "function KrENugjmoSjFTt(MXpLlaZs,MdWEsbKFB){return MXpLlaZs.indexOf(MdWEsbKFB);}" fullword ascii
    $s16 = "function pkkPjEmxU(OOjRynN,PgdsOV,selkaMxBqpNAA){GbqSEyiKuQbC=OOjRynN.split(selkaMxBqpNAA);qOeepyGQhHNvd = ciSBxcTkGkjPLydsUQcD[" ascii
    $s17 = "jQNtJaIUCyEaZe += GOZcBUdcEKuHzZP(JqCgynTtmCqajOmUp, pxZHGKxogjKw, UvSnJrFwzWIkCk);} while (hYguKcpXShjmqkcYjraxT < VNxOpPVPDzFY" ascii
    $s18 = "function bAmTYWrCycF(){return pkkPjEmxU(ciSBxcTkGkjPLydsUQcD[10],[2,4,8,10],ciSBxcTkGkjPLydsUQcD[11]);}" fullword ascii
    $s19 = "function GOZcBUdcEKuHzZP(kaFdgWjEwOqeXBAiUErbtnX,qYopYYrGUjTgTBDfZ,LtidLukJQXonfAcRmZ){return String.fromCharCode(kaFdgWjEwOqeXB" ascii
    $s20 = "var rTHILWaG = uHmvJSLnGDdp.createtextfile(fNAvqlAiXdR.ExpandEnvironmentStrings(ciSBxcTkGkjPLydsUQcD[2]+ciSBxcTkGkjPLydsUQcD[3])" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}