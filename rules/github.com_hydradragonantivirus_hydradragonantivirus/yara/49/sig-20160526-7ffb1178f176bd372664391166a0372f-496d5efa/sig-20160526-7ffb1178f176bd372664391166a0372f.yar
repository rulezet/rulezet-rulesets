rule sig_20160526_7ffb1178f176bd372664391166a0372f {
  meta:
    description = "datamaliciousorder - file 20160526_7ffb1178f176bd372664391166a0372f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6da66b09a44d9424e55288deedf2a8441bb9cb9229464dc94ff9bfc823119d40"

  strings:
    $s1  = " - 1))-199)) RONpDm += cBPkgTLEeLYqpMTJ(AHWUmDpYfyzZaelBHtAJRYs, KMspSDSNOFmRjqlm);else RONpDm += TajtuWkV(AHWUmDpYfyzZaelBHtAJR" ascii
    $s2  = "function njptnEJwwRAyS(ZCadKeufYwCow) {var OfqpzIPqmLV = gIzAmUgvMlDRmNe.join(TilJoDYySoUBhuncnilbX[0]);var AHWUmDpYfyzZaelBHtAJ" ascii
    $s3  = "WUmDpYfyzZaelBHtAJRYs);else if (OBVnkamUcbfmPqVMbb == (263 + Math.round((Math.pow(Math.sin(367), 2) + Math.pow(Math.cos(367), 2)" ascii
    $s4  = "function yQNnOvvclWgfzxVCUXBiT(XRBsJBTUWAbKuNbLlzJfUj,FARlKRuFzpAEKbWKSgeADX){return XRBsJBTUWAbKuNbLlzJfUj.charAt(FARlKRuFzpAEK" ascii
    $s5  = "function yQNnOvvclWgfzxVCUXBiT(XRBsJBTUWAbKuNbLlzJfUj,FARlKRuFzpAEKbWKSgeADX){return XRBsJBTUWAbKuNbLlzJfUj.charAt(FARlKRuFzpAEK" ascii
    $s6  = "function cBPkgTLEeLYqpMTJ(lQfxZrg,EzUjJAXvzoEaSPmfRDFyx){return String.fromCharCode(lQfxZrg,EzUjJAXvzoEaSPmfRDFyx);}" fullword ascii
    $s7  = "function np(pAQwyOcVx){return String.fromCharCode(pAQwyOcVx);}" fullword ascii
    $s8  = "function pITgEbArvQkAChlyZUzbm(yZQzpVt,aKDfafytuGYTyroyH){return yZQzpVt.indexOf(aKDfafytuGYTyroyH);}" fullword ascii
    $s9  = "function TajtuWkV(heWKrazChvWRPVBaonxSXSE,coYgLD,BYHyS){return String.fromCharCode(heWKrazChvWRPVBaonxSXSE,coYgLD,BYHyS);}" fullword ascii
    $s10 = "Ys, KMspSDSNOFmRjqlm, YnvkodCUFgNJuE);} while (bLCOLGK < ZCadKeufYwCow.length);return RONpDm;}" fullword ascii
    $s11 = "function njptnEJwwRAyS(ZCadKeufYwCow) {var OfqpzIPqmLV = gIzAmUgvMlDRmNe.join(TilJoDYySoUBhuncnilbX[0]);var AHWUmDpYfyzZaelBHtAJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}