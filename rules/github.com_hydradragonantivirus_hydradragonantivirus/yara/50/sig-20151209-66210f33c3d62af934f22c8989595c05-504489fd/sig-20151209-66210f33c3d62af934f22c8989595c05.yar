rule sig_20151209_66210f33c3d62af934f22c8989595c05 {
  meta:
    description = "datamaliciousorder - file 20151209_66210f33c3d62af934f22c8989595c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5376980faf7b9b8689bbbb816abc7126c55f7845bf108317b5f57dec950e9c43"

  strings:
    $s1  = "function SfYfPqA(wptxsgYURDcKvbtiskCIIDtzqejxDVMFOnOT) {return !isNaN(parseFloat(wptxsgYURDcKvbtiskCIIDtzqejxDVMFOnOT)) && isFin" ascii
    $s2  = "function SfYfPqA(wptxsgYURDcKvbtiskCIIDtzqejxDVMFOnOT) {return !isNaN(parseFloat(wptxsgYURDcKvbtiskCIIDtzqejxDVMFOnOT)) && isFin" ascii
    $s3  = "function DJdJj(tYvvEFPVjud,TLIIxzNsJlOSF,lahhnMLs){QZqU=parseInt(tYvvEFPVjud,TLIIxzNsJlOSF);HzySv=QZqU.toString(lahhnMLs);return" ascii
    $s4  = "+;}} return cOrFyhkPNee}" fullword ascii
    $s5  = "function HJeFRwWoJtZcYINEG(yklJe){cOrFyhkPNee= '';for(PVxkQJywTJc=(-224+224)/970; PVxkQJywTJc < (-242+432)/95; PVxkQJywTJc++) {k" ascii
    $s6  = "function tyuglwJZilRvoyqnIlSDKPOTGWBOmukfdeahbfLloHwDsVlTNPuKSU(pNhmutDKZadKY,oPicsDUwIOXsIO){ return jikHT[DJdJj(pNhmutDKZadKY[" ascii
    $s7  = "yqFiaYVk[PVxkQJywTJc]=(-531+531)/370; while(true) { if(kyqFiaYVk[PVxkQJywTJc] > yklJe[PVxkQJywTJc].length-(145+236)/381) { break" ascii
    $s8  = "function TOnyCiGHiYV(efvLYnyA,gKHCtt){return efvLYnyA.split(gKHCtt)}" fullword ascii
    $s9  = "function HJeFRwWoJtZcYINEG(yklJe){cOrFyhkPNee= '';for(PVxkQJywTJc=(-224+224)/970; PVxkQJywTJc < (-242+432)/95; PVxkQJywTJc++) {k" ascii
    $s10 = " HzySv;}function xlapzIxMmMaZjrE(gRhwGJtPrVLHBuoVz){eval(gRhwGJtPrVLHBuoVz)}" fullword ascii
    $s11 = "function tyuglwJZilRvoyqnIlSDKPOTGWBOmukfdeahbfLloHwDsVlTNPuKSU(pNhmutDKZadKY,oPicsDUwIOXsIO){ return jikHT[DJdJj(pNhmutDKZadKY[" ascii
    $s12 = "function DJdJj(tYvvEFPVjud,TLIIxzNsJlOSF,lahhnMLs){QZqU=parseInt(tYvvEFPVjud,TLIIxzNsJlOSF);HzySv=QZqU.toString(lahhnMLs);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}