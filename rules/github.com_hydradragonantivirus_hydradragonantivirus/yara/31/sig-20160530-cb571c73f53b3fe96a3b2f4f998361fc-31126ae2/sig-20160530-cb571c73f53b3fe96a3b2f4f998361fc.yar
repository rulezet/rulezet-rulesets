rule sig_20160530_cb571c73f53b3fe96a3b2f4f998361fc {
  meta:
    description = "datamaliciousorder - file 20160530_cb571c73f53b3fe96a3b2f4f998361fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abba28964bdd49c8e86ed16d79ca6359784a74e02a9a1f04b90e534e151cd1c7"

  strings:
    $s1  = "var WtUaosyS=function(){return WScript.CreateObject(GjfgINCTYypr[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function zDLpnrPjDVSczXyyONQYC(BrjTlDwqkQP,unNOEcEwgHbgVUqkbmxm){return BrjTlDwqkQP.charAt(unNOEcEwgHbgVUqkbmxm);}" fullword ascii
    $s3  = "function HnjdpIpryqgvYM(fLoSjjsHPqaftzKu,jhRds){return String.fromCharCode(fLoSjjsHPqaftzKu,jhRds);}" fullword ascii
    $s4  = "function iE(wkxuwMPznAfcuez){return String.fromCharCode(wkxuwMPznAfcuez);}" fullword ascii
    $s5  = "function cdHgM(SgNYzGBCiU,wxfzuZFWnQooFIQdTwtxz,UqbzPyEiafDxqRbZHSbC){return String.fromCharCode(SgNYzGBCiU,wxfzuZFWnQooFIQdTwtx" ascii
    $s6  = "var arZQvBZHPKP=function(){return new ActiveXObject(GjfgINCTYypr[1]);}();" fullword ascii
    $s7  = "function TunENtcIz(CCtaOcQzrXQLy) {var EgFhui = gVSJjUQBg.join(GjfgINCTYypr[7]);var qJnANR, uMRaWzoLTk, DoPxomAcEbMAq, wVlTahMCM" ascii
    $s8  = "function VHUEMiutbRPIvJ(){return vXSnaTXcDrQsBW(GjfgINCTYypr[9],[1,5,7],GjfgINCTYypr[10]);}" fullword ascii
    $s9  = "function cdHgM(SgNYzGBCiU,wxfzuZFWnQooFIQdTwtxz,UqbzPyEiafDxqRbZHSbC){return String.fromCharCode(SgNYzGBCiU,wxfzuZFWnQooFIQdTwtx" ascii
    $s10 = "(92)+GjfgINCTYypr[5],true);" fullword ascii
    $s11 = " == 64) fKDZenZNNKOanZwhiOtcIQ += HnjdpIpryqgvYM(qJnANR, uMRaWzoLTk);else fKDZenZNNKOanZwhiOtcIQ += cdHgM(qJnANR, uMRaWzoLTk, Do" ascii
    $s12 = "function WeghOCph(){return vXSnaTXcDrQsBW(GjfgINCTYypr[13],[0,3,6],GjfgINCTYypr[14]);}" fullword ascii
    $s13 = "PxomAcEbMAq);} while (zNaESyvllyrAhYpXiuQImK < CCtaOcQzrXQLy.length);return fKDZenZNNKOanZwhiOtcIQ;}" fullword ascii
    $s14 = "var eFtEUCID = arZQvBZHPKP.createtextfile(WtUaosyS.ExpandEnvironmentStrings(GjfgINCTYypr[3]+GjfgINCTYypr[4])+String.fromCharCode" ascii
    $s15 = "function XsONl(){return vXSnaTXcDrQsBW(GjfgINCTYypr[11],[2,4,8,10],GjfgINCTYypr[12]);}" fullword ascii
    $s16 = "function oWKDQSmTiRqL(URAHHAOAab,aChQdlibLYzvYJxqA){return URAHHAOAab.indexOf(aChQdlibLYzvYJxqA);}" fullword ascii
    $s17 = "mAcEbMAq = iBHcvPMWnzoJRn & 0xff;if (grijHLVilXBcsJZJY == 64) fKDZenZNNKOanZwhiOtcIQ += iE(qJnANR);else if (PGrvgbGgggEXXpzwMdrs" ascii
    $s18 = "function abxkamRpSXhsQQ(mhyGlTiIwerz,SDGmY) {var ERgLXHb=[GjfgINCTYypr[15]];mhyGlTiIwerz[ERgLXHb[0]]" fullword ascii
    $s19 = "function TunENtcIz(CCtaOcQzrXQLy) {var EgFhui = gVSJjUQBg.join(GjfgINCTYypr[7]);var qJnANR, uMRaWzoLTk, DoPxomAcEbMAq, wVlTahMCM" ascii
    $s20 = "function fXPXnmbzbm(){return WtUaosyS.ExpandEnvironmentStrings(VHUEMiutbRPIvJ())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}