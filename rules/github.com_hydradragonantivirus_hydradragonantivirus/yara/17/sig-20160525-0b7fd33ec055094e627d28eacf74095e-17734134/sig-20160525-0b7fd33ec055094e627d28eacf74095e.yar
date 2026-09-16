rule sig_20160525_0b7fd33ec055094e627d28eacf74095e {
  meta:
    description = "datamaliciousorder - file 20160525_0b7fd33ec055094e627d28eacf74095e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f660724ede1e4fed94396b2909a2133951d95d6db96862f9adaafdef74191a75"

  strings:
    $s1  = "else if (lrZuzpwwBCVnRmfWZXCM == (884 + Math.round((Math.pow(Math.sin(810), 2) + Math.pow(Math.cos(810), 2) - 1))-820)) UwPTeVAE" ascii
    $s2  = "12), 2) + Math.pow(Math.cos(512), 2) - 1))-384) | lrZuzpwwBCVnRmfWZXCM;YnkhWfDWSmyiJhaIQXs = hqFIbtDQev>> (94 + Math.round((Math" ascii
    $s3  = "function CVxpkcTsZGK(UStIeLCtxCDWF) {var VGvNnTgMjPQ = sYldHT.join(rxSLphlH[0]);var YnkhWfDWSmyiJhaIQXs, gQCpArfUCQezZ, jRioOSSp" ascii
    $s4  = "function kukmOOkXg(TziZvEfrEFrKLMS,poztjisRoRQlneZBmoaa){return TziZvEfrEFrKLMS.charAt(poztjisRoRQlneZBmoaa);}" fullword ascii
    $s5  = "iJhaIQXs, gQCpArfUCQezZ, jRioOSSpomNGON);} while (uKCKzpZhatj < UStIeLCtxCDWF.length);return UwPTeVAEteeURMMtvLfDT;}" fullword ascii
    $s6  = "teeURMMtvLfDT += RguvvrNQ(YnkhWfDWSmyiJhaIQXs, gQCpArfUCQezZ);else UwPTeVAEteeURMMtvLfDT += gPrGzLOELkkLpYscoCZcTpvb(YnkhWfDWSmy" ascii
    $s7  = "function RguvvrNQ(qhfWfsOsitWRRlYFiOZojXz,HjAZaSGUtulGyJq){return String.fromCharCode(qhfWfsOsitWRRlYFiOZojXz,HjAZaSGUtulGyJq);}" ascii
    $s8  = "function CVxpkcTsZGK(UStIeLCtxCDWF) {var VGvNnTgMjPQ = sYldHT.join(rxSLphlH[0]);var YnkhWfDWSmyiJhaIQXs, gQCpArfUCQezZ, jRioOSSp" ascii
    $s9  = "function yFPuFErmBr(QqQvUMYbjrSlTBQUxMaLf,AEPmtqqGFf){return QqQvUMYbjrSlTBQUxMaLf.indexOf(AEPmtqqGFf);}" fullword ascii
    $s10 = "function gPrGzLOELkkLpYscoCZcTpvb(GkJQvIoEUDr,slCpTOaG,rtTYooDBToUA){return String.fromCharCode(GkJQvIoEUDr,slCpTOaG,rtTYooDBToU" ascii
    $s11 = "function gPrGzLOELkkLpYscoCZcTpvb(GkJQvIoEUDr,slCpTOaG,rtTYooDBToUA){return String.fromCharCode(GkJQvIoEUDr,slCpTOaG,rtTYooDBToU" ascii
    $s12 = "function iXk(trIzKngOcb){return String.fromCharCode(trIzKngOcb);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}