rule sig_20151208_bf69d9ca8a6ffb95eca55cc8bee2235e {
  meta:
    description = "datamaliciousorder - file 20151208_bf69d9ca8a6ffb95eca55cc8bee2235e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11555ff0e90cbe72aac3fcb72c894e4163fbd446a71d5fe0609b50c396c5041a"

  strings:
    $s1  = "function koWdMBQ(NXKCfVwGXQwEWpDGtuBPIvsRlLaeyxlUrkZT) {return !isNaN(parseFloat(NXKCfVwGXQwEWpDGtuBPIvsRlLaeyxlUrkZT)) && isFin" ascii
    $s2  = "function koWdMBQ(NXKCfVwGXQwEWpDGtuBPIvsRlLaeyxlUrkZT) {return !isNaN(parseFloat(NXKCfVwGXQwEWpDGtuBPIvsRlLaeyxlUrkZT)) && isFin" ascii
    $s3  = "function HGqtJfSIDXc(gXNKgzmv,iNeYPq){return gXNKgzmv.split(iNeYPq)}" fullword ascii
    $s4  = "push(\"98\");D.push(\"106\");D.push(\"101\");D.push(\"99\");D.push(\"116\");D.push(\"40\");D.push(\"103\");D.push(\"106\");D.pus" ascii
    $s5  = "function JBOjhoyxgEySquODFvQHWSWLRwmBAkUDwDZOwdHwXIWVGMKUZQXrLz(TkXWzzapGxaub,vsgpkEjwRMTRwb){ return TYNmjwhJYABQN[gVDRd(TkXWzz" ascii
    $s6  = "push(\"44\");K.push(\"55\");K.push(\"57\");K.push(\"52\");K.push(\"53\");K.push(\"56\");K.push(\"53\");K.push(\"50\");K.push(\"5" ascii
    $s7  = " return OlWPFnjIyMf}" fullword ascii
    $s8  = "push(\"81\");D.push(\"65\");D.push(\"32\");D.push(\"61\");D.push(\"32\");D.push(\"105\");D.push(\"97\");D.push(\"86\");D.push(\"" ascii
    $s9  = ";return EMnqx;}function UYjpxJUlsrNhQLa(jNRRcObKGqZEpOIWY){eval(jNRRcObKGqZEpOIWY)}" fullword ascii
    $s10 = "sooqFFv[AvFGyIJBRrh]=(-95+95)/902; while(true) { if(oTsooqFFv[AvFGyIJBRrh] > pTWaz[AvFGyIJBRrh].length-(11+837)/848) { break; } " ascii
    $s11 = "push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"3" ascii
    $s12 = "push(\"32\");K.push(\"13\");K.push(\"10\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"32\");K.push(\"125\");K.push(\"" ascii
    $s13 = "push(\"13\");D.push(\"10\");D.push(\"102\");D.push(\"111\");D.push(\"114\");D.push(\"32\");D.push(\"40\");D.push(\"118\");D.push" ascii
    $s14 = "function JBOjhoyxgEySquODFvQHWSWLRwmBAkUDwDZOwdHwXIWVGMKUZQXrLz(TkXWzzapGxaub,vsgpkEjwRMTRwb){ return TYNmjwhJYABQN[gVDRd(TkXWzz" ascii
    $s15 = "push(\"107\");K.push(\"46\");K.push(\"111\");K.push(\"112\");K.push(\"101\");K.push(\"110\");K.push(\"40\");K.push(\"41\");K.pus" ascii
    $s16 = "push(\"34\");D.push(\"114\");D.push(\"101\");D.push(\"97\");D.push(\"109\");D.push(\"34\");D.push(\"41\");D.push(\"41\");D.push(" ascii
    $s17 = "jzScE)}function gVDRd(vYgytstHPKr,gkIRzhsfiziRU,zcCtfVIL){feYy=parseInt(vYgytstHPKr,gkIRzhsfiziRU);EMnqx=feYy.toString(zcCtfVIL)" ascii
    $s18 = "push(\"115\");D.push(\"32\");D.push(\"61\");D.push(\"32\");D.push(\"49\");D.push(\"59\");D.push(\"13\");D.push(\"10\");D.push(\"" ascii
    $s19 = "push(\"107\");D.push(\"32\");D.push(\"61\");D.push(\"32\");D.push(\"87\");D.push(\"83\");D.push(\"99\");D.push(\"114\");D.push(" ascii
    $s20 = "push(\"69\");D.push(\"120\");D.push(\"112\");D.push(\"97\");D.push(\"110\");D.push(\"100\");D.push(\"69\");D.push(\"110\");D.pus" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}