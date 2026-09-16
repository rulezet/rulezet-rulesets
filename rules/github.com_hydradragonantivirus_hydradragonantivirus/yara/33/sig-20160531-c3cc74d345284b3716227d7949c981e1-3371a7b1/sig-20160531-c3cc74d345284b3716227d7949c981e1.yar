rule sig_20160531_c3cc74d345284b3716227d7949c981e1 {
  meta:
    description = "datamaliciousorder - file 20160531_c3cc74d345284b3716227d7949c981e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f74086f0029bd2bf44dc0db44fe9c20e50c9a5a92bfba4a9cc007ff60ad25a9"

  strings:
    $s1  = "var GWhMGpZgqDwdXk=function(){return WScript.CreateObject(FoiAZvaLIrLnHCceeP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function CwcqAhoBNMUfG(KaVsQokfZj,kIMEupkBoyW){return KaVsQokfZj.charAt(kIMEupkBoyW);}" fullword ascii
    $s3  = "length);}" fullword ascii
    $s4  = "(brlxESJlobt,0x1,0x0)}function zOriOZAjfXJwM(MDoAkmtEVK,LQKMWcMqMRSkBw,xYXVZSmO){var hPJOTIungTr=MDoAkmtEVK.createtextfile(LQKMW" ascii
    $s5  = "WUwe & 0xff;if (TOYuOWAWra == 64) VnwjbSSYmUBgyRl += I(dXKQMbgonVeNlWVDPoBklMPd);else if (DhKxTvsDP == 64) VnwjbSSYmUBgyRl += HK" ascii
    $s6  = "function I(EIAfbtAjNLDBWlBYL){return String.fromCharCode(EIAfbtAjNLDBWlBYL);}" fullword ascii
    $s7  = "var SfnmNpdBFVIDc=function(){return new ActiveXObject(FoiAZvaLIrLnHCceeP[1]);}();" fullword ascii
    $s8  = " RmYhoUbOQBPffYwa);} while (pXwUjRSIEKHCgRclsFJNtG < AjYUFFIaoXPxX.length);return VnwjbSSYmUBgyRl;}" fullword ascii
    $s9  = "function VVuNOzkb(hcxYeFU,zbiKtZe,gonzxVqWIDX){ysztNiPiJY=hcxYeFU.split(gonzxVqWIDX);TZpaTHjDf = FoiAZvaLIrLnHCceeP[0];for(XOsVR" ascii
    $s10 = "function wpaRBjIaR(SKDtnTglArFgwNsm,snUbWatwTGjaTChwtWhQxbN,nFMbpMCEPZdSTnbduAr){return String.fromCharCode(SKDtnTglArFgwNsm,snU" ascii
    $s11 = "cMqMRSkBw,true);hPJOTIungTr.WriteLine(xYXVZSmO);hPJOTIungTr.Close();}" fullword ascii
    $s12 = "function iFJkWxxiHL(){return GWhMGpZgqDwdXk.ExpandEnvironmentStrings(ywDzUiUmIxIBLJ())}" fullword ascii
    $s13 = "push(\"v\");ewKbUwcDNecpMGnojFxCtnCe.push(\"w\");ewKbUwcDNecpMGnojFxCtnCe.push(\"x\");ewKbUwcDNecpMGnojFxCtnCe.push(\"y\");ewKbU" ascii
    $s14 = "function ucVIJI(FsavnVMNPBpAnO,brlxESJlobt) {var SOatD=[FoiAZvaLIrLnHCceeP[15]];FsavnVMNPBpAnO[SOatD[0]]" fullword ascii
    $s15 = "function wpaRBjIaR(SKDtnTglArFgwNsm,snUbWatwTGjaTChwtWhQxbN,nFMbpMCEPZdSTnbduAr){return String.fromCharCode(SKDtnTglArFgwNsm,snU" ascii
    $s16 = "Code(92)+FoiAZvaLIrLnHCceeP[5],RZPDa);" fullword ascii
    $s17 = "VoBn=0;XOsVRVoBn<zbiKtZe.length;XOsVRVoBn++) {TZpaTHjDf+=ysztNiPiJY[zbiKtZe[XOsVRVoBn]];}return TZpaTHjDf.substring(3,TZpaTHjDf." ascii
    $s18 = "function aNfrIumH(AjYUFFIaoXPxX) {var pKXTLBcqvH = ewKbUwcDNecpMGnojFxCtnCe.join(FoiAZvaLIrLnHCceeP[7]);var dXKQMbgonVeNlWVDPoBk" ascii
    $s19 = "function AEsLplSaCsVeS(){return VVuNOzkb(FoiAZvaLIrLnHCceeP[11],[2,4,8,10],FoiAZvaLIrLnHCceeP[12]);}" fullword ascii
    $s20 = "function ywDzUiUmIxIBLJ(){return VVuNOzkb(FoiAZvaLIrLnHCceeP[9],[1,5,7],FoiAZvaLIrLnHCceeP[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}