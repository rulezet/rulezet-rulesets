rule sig_20151210_7707cb34e1263eec93786aabc247318d {
  meta:
    description = "datamaliciousorder - file 20151210_7707cb34e1263eec93786aabc247318d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2bba0f6847201533dc4ed82f3dc146ffa1444fa36f5f64b91525e114cf4c8ae"

  strings:
    $s1  = "function LTuUzdq(hoQFQqVENstArLdYYcWLLuWqcowTHniwnvwW) {return !isNaN(parseFloat(hoQFQqVENstArLdYYcWLLuWqcowTHniwnvwW)) && isFin" ascii
    $s2  = "function LTuUzdq(hoQFQqVENstArLdYYcWLLuWqcowTHniwnvwW) {return !isNaN(parseFloat(hoQFQqVENstArLdYYcWLLuWqcowTHniwnvwW)) && isFin" ascii
    $s3  = "fIXOGOA=(-145+145)/708;while(true){if(fIXOGOA>=(91751+665)/722){break;}gJWTMmipDMvpT[fIXOGOA]=String.fromCharCode(fIXOGOA);fIXOG" ascii
    $s4  = "function svkkaHdnjNl(xyxdjanb,pXRKnS){return xyxdjanb.split(pXRKnS)}" fullword ascii
    $s5  = "fIXOGOA=(-145+145)/708;while(true){if(fIXOGOA>=(91751+665)/722){break;}gJWTMmipDMvpT[fIXOGOA]=String.fromCharCode(fIXOGOA);fIXOG" ascii
    $s6  = "function cIdrGIAUSzMbKIUxbXIUhDUyRelmHydKAbvqgudPAQYkCQKsfSNVSD(zDeeBSIorCOfe,YqZjZRYElFlOJt){ return gJWTMmipDMvpT[wfxql(zDeeBS" ascii
    $s7  = " TILGK;}function eDshbKCDKJYVIGs(GACfDBbdKwCtMErAg){eval(GACfDBbdKwCtMErAg)}" fullword ascii
    $s8  = "function wfxql(AuOXHyCeuGp,CvYitldkGpizA,quGocWdB){zSbl=parseInt(AuOXHyCeuGp,CvYitldkGpizA);TILGK=zSbl.toString(quGocWdB);return" ascii
    $s9  = "function wfxql(AuOXHyCeuGp,CvYitldkGpizA,quGocWdB){zSbl=parseInt(AuOXHyCeuGp,CvYitldkGpizA);TILGK=zSbl.toString(quGocWdB);return" ascii
    $s10 = "function ssrdFozSUqLptyrIr(KvnSq){sonzytyOSqD= '';for(JvjiTBerjOw=(-405+405)/321; JvjiTBerjOw < (769+807)/788; JvjiTBerjOw++) {g" ascii
    $s11 = "function ssrdFozSUqLptyrIr(KvnSq){sonzytyOSqD= '';for(JvjiTBerjOw=(-405+405)/321; JvjiTBerjOw < (769+807)/788; JvjiTBerjOw++) {g" ascii
    $s12 = "function cIdrGIAUSzMbKIUxbXIUhDUyRelmHydKAbvqgudPAQYkCQKsfSNVSD(zDeeBSIorCOfe,YqZjZRYElFlOJt){ return gJWTMmipDMvpT[wfxql(zDeeBS" ascii
    $s13 = "SMZNrxwF[JvjiTBerjOw]=(-307+307)/147; while(true) { if(gSMZNrxwF[JvjiTBerjOw] > KvnSq[JvjiTBerjOw].length-(-858+880)/22) { break" ascii
    $s14 = "+;}} return sonzytyOSqD}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}