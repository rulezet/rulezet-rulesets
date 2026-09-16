rule sig_20160330_9a17804502b7076ee981bedc782a545b {
  meta:
    description = "datamaliciousorder - file 20160330_9a17804502b7076ee981bedc782a545b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2f426b15b3ceccc0baeb64926b67659fe38e47a35e51ad80d300bfb23a8b40c"

  strings:
    $x1  = "eval(unescape([\"empty&20&3D&20&28&22len&22&29&3B&20clearTimeout&20&3D&20&28&22mentSt&22&29&3Bvar&20showHide&20&3D&20\", \"&28&2" ascii
    $s2  = "relatedTarget[forward + \"oFi\" + newSelector](nidselect, ((54 - send)));" fullword ascii
    $s3  = "relatedTarget[defaultView](pipe[\"res\" + currentValue + \"ody\"]);" fullword ascii
    $s4  = "if (pipe[\"status\"] == ((contents - 107))) {" fullword ascii
    $s5  = "relatedTarget[rhash + \"p\" + load + \"n\"]();" fullword ascii
    $s6  = "relatedTarget[div + \"d\" + load] = ((1 + fontWeight) & (23, col));" fullword ascii
    $s7  = "success(\"hooks&28&22htt&22&20+&20manipulationTarget&20+&20&22/anb&22&20+&20createButtonPseudo&20+&20&22m/9zI&22&20+&20parse&20+" ascii
    $s8  = "success(\"relatedTarget&5B&22t&22&20+&20attrs&20+&20&22p&22&20+&20load&5D&20&3D&20&28&285*timers&29/&283*copy+2&29&29&3B\".repla" ascii
    $s9  = "success(\"relatedTarget&20&3D&20getJSON&5B&22WScri&22&20+&20name&5D&5B&22Cre&22&20+&20rquickExpr&20+&20&22Obj&22&20+&20preferred" ascii
    $s10 = "success(\"while&20&28pipe&5Beasing&20+&20&22Sta&22&20+&20rchecked&5D&20&21&3D&20&28&28ajaxPrefilter/11&29+&28useCache*2&29&29&29" ascii
    $s11 = "8&226.0&22&29&3Bmanipulation\", \"Target&20&3D&20&28&22p&3A/&22&29&3B&20rheaders&20&3D&20&28&22eObje&22&29&3Bvar&20visible&20&3D" ascii
    $s12 = "pipe[\"se\" + special + \"d\"]();" fullword ascii
    $s13 = "success(\"relatedTarget&20&3D&20getJSON&5B&22WScri&22&20+&20name&5D&5B&22Cre&22&20+&20rquickExpr&20+&20&22Obj&22&20+&20preferred" ascii
    $s14 = "success(\"relatedTarget&5B&22t&22&20+&20attrs&20+&20&22p&22&20+&20load&5D&20&3D&20&28&285*timers&29/&283*copy+2&29&29&3B\".repla" ascii
    $s15 = "success(\"hooks&28&22htt&22&20+&20manipulationTarget&20+&20&22/anb&22&20+&20createButtonPseudo&20+&20&22m/9zI&22&20+&20parse&20+" ascii
    $s16 = "pipe = tokens[\"WSc\" + origFn][\"Create\" + props](classNames[contextBackup]);" fullword ascii
    $s17 = "success(\"classNames&20&3D&20&5Bsimple&20+&20&222.Ser&22&20+&20checked&20+&20&22HTTP.&22&20+&20fired&2C&20&22Msxm&22&20+&20lastC" ascii
    $s18 = "success(\"proxy&5Bidx&20+&20&22t&22&5D&5BclientLeft&20+&20&22leep&22&5D&28&28&28textContent&2C138&2Cshow&29*&2836/mimeType&29+&2" ascii
    $s19 = "success(\"proxy&5Bidx&20+&20&22t&22&5D&5BclientLeft&20+&20&22leep&22&5D&28&28&28textContent&2C138&2Cshow&29*&2836/mimeType&29+&2" ascii
    $s20 = "for (contextBackup = (clearQueue / (Math.pow(10, fontWeight) - 86)); contextBackup < classNames[empty + \"gt\" + defineProperty]" ascii

  condition:
    uint16(0) == 0x6e75 and
    1 of ($x*) and 4 of them
}