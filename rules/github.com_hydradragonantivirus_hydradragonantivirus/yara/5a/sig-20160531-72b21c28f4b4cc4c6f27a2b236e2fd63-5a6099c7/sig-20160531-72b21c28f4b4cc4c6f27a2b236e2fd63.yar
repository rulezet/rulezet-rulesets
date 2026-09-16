rule sig_20160531_72b21c28f4b4cc4c6f27a2b236e2fd63 {
  meta:
    description = "datamaliciousorder - file 20160531_72b21c28f4b4cc4c6f27a2b236e2fd63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e7cf6d3fddcca311782bec68e2693d63311eef72f226084989c47a60891c198"

  strings:
    $s1  = "var cmBXZsQALIef=function(){return WScript.CreateObject(UzHjUpoCpHQLdbR[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function JRNJPvJHPZv(CsMmBItLVmkXHIMCLxuRI,kbyAmgRurn){return CsMmBItLVmkXHIMCLxuRI.charAt(kbyAmgRurn);}" fullword ascii
    $s3  = "GlJrgGlDmQn.length);return iTvdcvnGtCieAY;}" fullword ascii
    $s4  = "function kOZPRYmNfcSZ(GIYeUbR,ewAxMaqUp) {var hceNRrnNOGIdrF=[UzHjUpoCpHQLdbR[15]];GIYeUbR[hceNRrnNOGIdrF[0]]" fullword ascii
    $s5  = "function YrJgmebOnYpntW(lnGlJrgGlDmQn) {var YtGhFBhaSaAbeUdJlTp = eldIkItsBuxmAvq.join(UzHjUpoCpHQLdbR[7]);var etYwF, xqMUMMqWzK" ascii
    $s6  = "function LGzPIb(AMZBeSIKJdfvwV,vcwDNYikfFilQfJGSUkwnG){return AMZBeSIKJdfvwV.indexOf(vcwDNYikfFilQfJGSUkwnG);}" fullword ascii
    $s7  = "aTMXIPgbY,true);UKZUevXLMnch.WriteLine(sdKTGMmMRqe);UKZUevXLMnch.Close();}" fullword ascii
    $s8  = "function YrJgmebOnYpntW(lnGlJrgGlDmQn) {var YtGhFBhaSaAbeUdJlTp = eldIkItsBuxmAvq.join(UzHjUpoCpHQLdbR[7]);var etYwF, xqMUMMqWzK" ascii
    $s9  = "xqMUMMqWzKaEn);else iTvdcvnGtCieAY += IeOVbqqKLFDjaMyWUBuXy(etYwF, xqMUMMqWzKaEn, DikPQM);} while (KpKlqRSHRzWOURxLWItERzzE < ln" ascii
    $s10 = "function arzQswbcRR(){return nzLRR(UzHjUpoCpHQLdbR[11],[2,4,8,10],UzHjUpoCpHQLdbR[12]);}" fullword ascii
    $s11 = "function iCTaSSZPz(){return nzLRR(UzHjUpoCpHQLdbR[9],[1,5,7],UzHjUpoCpHQLdbR[10]);}" fullword ascii
    $s12 = "(ewAxMaqUp,0x1,0x0)}function DekIBgEMS(KwZjJHoGuWG,tvbxeaTMXIPgbY,sdKTGMmMRqe){var UKZUevXLMnch=KwZjJHoGuWG.createtextfile(tvbxe" ascii
    $s13 = "function IeOVbqqKLFDjaMyWUBuXy(duJGfFeQCRZgOGBtqBYIOne,dcgCuTABjrNfCUNLucSot,zPVzOQMiVpSQMMHuimLa){return String.fromCharCode(du" ascii
    $s14 = "f (kaflAqlJfrOkJSGuzlYM == 64) iTvdcvnGtCieAY += t(etYwF);else if (WfionWp == 64) iTvdcvnGtCieAY += XLgEYYVYNkSGClkKsCYj(etYwF, " ascii
    $s15 = "function IeOVbqqKLFDjaMyWUBuXy(duJGfFeQCRZgOGBtqBYIOne,dcgCuTABjrNfCUNLucSot,zPVzOQMiVpSQMMHuimLa){return String.fromCharCode(du" ascii
    $s16 = "function TtpxnpU(){return nzLRR(UzHjUpoCpHQLdbR[13],[0,3,6],UzHjUpoCpHQLdbR[14]);}" fullword ascii
    $s17 = "dhZUjUWg=0;nVKidhZUjUWg<GtlPO.length;nVKidhZUjUWg++) {QzKosBEtFSevv+=OgliaaQ[GtlPO[nVKidhZUjUWg]];}return QzKosBEtFSevv.substrin" ascii
    $s18 = "function mcHlK(){return cmBXZsQALIef.ExpandEnvironmentStrings(iCTaSSZPz())}" fullword ascii
    $s19 = "function XLgEYYVYNkSGClkKsCYj(UZJpCWoBsuXGEhTVhE,vpIjMOHbAwaharrCObazZ){return String.fromCharCode(UZJpCWoBsuXGEhTVhE,vpIjMOHbAw" ascii
    $s20 = "function t(oFsXmReyDkEX){return String.fromCharCode(oFsXmReyDkEX);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}