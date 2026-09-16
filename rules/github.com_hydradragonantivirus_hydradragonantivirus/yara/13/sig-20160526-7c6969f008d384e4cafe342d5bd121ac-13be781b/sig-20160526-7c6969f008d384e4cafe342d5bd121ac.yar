rule sig_20160526_7c6969f008d384e4cafe342d5bd121ac {
  meta:
    description = "datamaliciousorder - file 20160526_7c6969f008d384e4cafe342d5bd121ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f78a069fe69a3682ce329ad9534d812d66bf50b8819d360ea052f682beb4955c"

  strings:
    $s1  = "Math.pow(Math.cos(430), 2) - 1))-123)) OFGaehrJTOnGaOTAkiAP += uPnMiZvwD(equfbHxHPhaLMmUgeYeiQlW, TdDDrhrMtfPdZnLkyVSHN);else OF" ascii
    $s2  = "function qljVNfer(JJQfLxuPyfCdE) {var FCRrbpIHAZYtjf = fTFFeAILxbMUYxGML.join(XEDKerj[0]);var equfbHxHPhaLMmUgeYeiQlW, TdDDrhrMt" ascii
    $s3  = "ehrJTOnGaOTAkiAP += pC(equfbHxHPhaLMmUgeYeiQlW);else if (yvLrCZlPQAfYxPfRAeb == (187 + Math.round((Math.pow(Math.sin(430), 2) + " ascii
    $s4  = "function qljVNfer(JJQfLxuPyfCdE) {var FCRrbpIHAZYtjf = fTFFeAILxbMUYxGML.join(XEDKerj[0]);var equfbHxHPhaLMmUgeYeiQlW, TdDDrhrMt" ascii
    $s5  = "function GSWkScSGdf(mgDsUpYkHShrRqjaHtaoPl,DkDDLGWHrvOAsxMcIDBFEA){return mgDsUpYkHShrRqjaHtaoPl.charAt(DkDDLGWHrvOAsxMcIDBFEA);" ascii
    $s6  = "function GSWkScSGdf(mgDsUpYkHShrRqjaHtaoPl,DkDDLGWHrvOAsxMcIDBFEA){return mgDsUpYkHShrRqjaHtaoPl.charAt(DkDDLGWHrvOAsxMcIDBFEA);" ascii
    $s7  = "GaehrJTOnGaOTAkiAP += VEmZVqQ(equfbHxHPhaLMmUgeYeiQlW, TdDDrhrMtfPdZnLkyVSHN, hrrKzUZwHfJTtLAvj);} while (eESZix < JJQfLxuPyfCdE" ascii
    $s8  = "function pC(oLBFlcmjesqqXbfyckhEX){return String.fromCharCode(oLBFlcmjesqqXbfyckhEX);}" fullword ascii
    $s9  = ".length);return OFGaehrJTOnGaOTAkiAP;}" fullword ascii
    $s10 = "function sPqakeDVHIUaKXJCvbE(bIZgWMmqRILKgCRUgV,lHmLNyMGblhOzBCrGmQWxOw){return bIZgWMmqRILKgCRUgV.indexOf(lHmLNyMGblhOzBCrGmQWx" ascii
    $s11 = "function uPnMiZvwD(EqYWmUGPrOoW,HaalGgiPpsgaHXqWRPEqrBv){return String.fromCharCode(EqYWmUGPrOoW,HaalGgiPpsgaHXqWRPEqrBv);}" fullword ascii
    $s12 = "function sPqakeDVHIUaKXJCvbE(bIZgWMmqRILKgCRUgV,lHmLNyMGblhOzBCrGmQWxOw){return bIZgWMmqRILKgCRUgV.indexOf(lHmLNyMGblhOzBCrGmQWx" ascii
    $s13 = "function VEmZVqQ(bGbTGohyKGANFToaIpUUDJY,UTQvblOCVAWK,DdHDRgZafFNEqcr){return String.fromCharCode(bGbTGohyKGANFToaIpUUDJY,UTQvbl" ascii
    $s14 = "function VEmZVqQ(bGbTGohyKGANFToaIpUUDJY,UTQvblOCVAWK,DdHDRgZafFNEqcr){return String.fromCharCode(bGbTGohyKGANFToaIpUUDJY,UTQvbl" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}