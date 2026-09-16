rule sig_20160531_5880638658991cb3c43f1b4d28a1a868 {
  meta:
    description = "datamaliciousorder - file 20160531_5880638658991cb3c43f1b4d28a1a868.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ffde42287ff644745224cdb9e027d769e6268df913ca7976ea68ea63a2329d2"

  strings:
    $s1  = "var EmCqN=function(){return WScript.CreateObject(nNSKV[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function SRVSQHWwKqwiWDxXVwTN(bJUdHtzHvoCn,sBCMFWUJTgyNnNwmKuMwQD){return bJUdHtzHvoCn.charAt(sBCMFWUJTgyNnNwmKuMwQD);}" fullword ascii
    $s3  = "function bdgugbjaxZ(rLZDEAsgFeCqb) {var xeuxTCbbytw = ggpkWwaDyDvWR.join(nNSKV[7]);var BtKuQGnQycSODOxhMM, TAwjLxgrSioj, LiTJvMO" ascii
    $s4  = "MOOKuROsRFSmRWVGHC = cMDyzbeYq & 0xff;if (WqgCSZEWcy == 64) TCCqcweHFyQafy += mb(BtKuQGnQycSODOxhMM);else if (vMXrAfaEmviSLqYdwY" ascii
    $s5  = "function KYTGnUugYaVaJwH(OJpluQXuSdOfMG,ASYktVIkwnbKxalWERotOKdj,RFrBTRAI){return String.fromCharCode(OJpluQXuSdOfMG,ASYktVIkwnb" ascii
    $s6  = "function IoUmg(KPffE,TICbqeKpoAm,TGMnFmtczgdPoP){LwZXTFKERkEwPE=KPffE.split(TGMnFmtczgdPoP);HjDmaAxjWbPQeK = nNSKV[0];for(VGOwUU" ascii
    $s7  = "function butoNvmyraTamFBXFjxE(wtjnteLFNlUDSwgrFsfIF,XzokLv){return wtjnteLFNlUDSwgrFsfIF.indexOf(XzokLv);}" fullword ascii
    $s8  = " TAwjLxgrSioj, LiTJvMOOKuROsRFSmRWVGHC);} while (IWOakvOFRSXehMaW < rLZDEAsgFeCqb.length);return TCCqcweHFyQafy;}" fullword ascii
    $s9  = "function sHeqOdAZmqLxCk(aXADaHhuKmzo,zIvaQn) {var IIZHrjR=[nNSKV[15]];aXADaHhuKmzo[IIZHrjR[0]]" fullword ascii
    $s10 = "function FptYQCH(){return IoUmg(nNSKV[9],[1,5,7],nNSKV[10]);}" fullword ascii
    $s11 = "(zIvaQn,0x1,0x0)}function dciHOBFlmkmEY(fbPiVHfC,OmXWcNEKjTIrxt,hjzmMSQklC){var JOejcotA=fbPiVHfC.createtextfile(OmXWcNEKjTIrxt," ascii
    $s12 = "function dlKpcMann(){return EmCqN.ExpandEnvironmentStrings(FptYQCH())}" fullword ascii
    $s13 = "true);JOejcotA.WriteLine(hjzmMSQklC);JOejcotA.Close();}" fullword ascii
    $s14 = "function wlAOAV(eBKyZiqPfiooxg,lDuvMd){return String.fromCharCode(eBKyZiqPfiooxg,lDuvMd);}" fullword ascii
    $s15 = "function IoUmg(KPffE,TICbqeKpoAm,TGMnFmtczgdPoP){LwZXTFKERkEwPE=KPffE.split(TGMnFmtczgdPoP);HjDmaAxjWbPQeK = nNSKV[0];for(VGOwUU" ascii
    $s16 = "var vnBEgBTuhJy=function(){return new ActiveXObject(nNSKV[1]);}();" fullword ascii
    $s17 = "function KYTGnUugYaVaJwH(OJpluQXuSdOfMG,ASYktVIkwnbKxalWERotOKdj,RFrBTRAI){return String.fromCharCode(OJpluQXuSdOfMG,ASYktVIkwnb" ascii
    $s18 = "(zIvaQn,0x1,0x0)}function dciHOBFlmkmEY(fbPiVHfC,OmXWcNEKjTIrxt,hjzmMSQklC){var JOejcotA=fbPiVHfC.createtextfile(OmXWcNEKjTIrxt," ascii
    $s19 = "IFl == 64) TCCqcweHFyQafy += wlAOAV(BtKuQGnQycSODOxhMM, TAwjLxgrSioj);else TCCqcweHFyQafy += KYTGnUugYaVaJwH(BtKuQGnQycSODOxhMM," ascii
    $s20 = "function mb(GGPzlTkm){return String.fromCharCode(GGPzlTkm);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}