rule sig_20160330_ac8aa4324f979a46d8464aa2f11e39dd {
  meta:
    description = "datamaliciousorder - file 20160330_ac8aa4324f979a46d8464aa2f11e39dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25fba86fc6061a3fdadbebf64d5c7582bc817100ce3f689d75e366e065d82dbb"

  strings:
    $s1  = "eval(unescape([\"overflow&20&3D&20&28&22Slee&22&29&2C&20status&20&3D&20&281292&29&2C&20createButtonPseudo&20&3D&20&28\", \"&22yS" ascii
    $s2  = "remove(\"preferredDoc&20&3D&20&5B&22Msx&22&20+&20parseHTML&20+&20&22.Se&22&20+&20maxIterations&20+&20&22LHTTP.&22&20+&20structur" ascii
    $s3  = "postDispatch[subtract + \"pt\"][count](((rbuggyMatches - 72043) / (cur | 7)));" fullword ascii
    $s4  = "remove(\"while&20&28overrideMimeType&5B&22read&22&20+&20createButtonPseudo&5D&20&21&3D&20&28&28Math.pow&283&2C&20hasDuplicate&29" ascii
    $s5  = "if (overrideMimeType[\"statu\" + doAnimation] == ((Math.pow(trigger, 2) - buildFragment) * 2 + (fn, 17, cache))) {" fullword ascii
    $s6  = "remove(\"overrideMimeType&5BstartLength&20+&20&22p&22&20+&20Data&5D&28&22G&22&20+&20stopPropagation&2C&20&22http&22&20+&20preven" ascii
    $s7  = "triggered[callbackInverse + \"rite\"](overrideMimeType[xhrSupported + \"onseB\" + rsubmittable]);" fullword ascii
    $s8  = "triggered[multipleContexts + \"File\"](stateVal, (41 - (max * 13)));" fullword ascii
    $s9  = "remove(\"overrideMimeType&5BstartLength&20+&20&22p&22&20+&20Data&5D&28&22G&22&20+&20stopPropagation&2C&20&22http&22&20+&20preven" ascii
    $s10 = "remove(\"stateVal&20&3D&20compiled&5B&22Expan&22&20+&20PI&20+&20&22vir&22&20+&20computeStyleTests&20+&20&22ntStr&22&20+&20conver" ascii
    $s11 = "remove(\"while&20&28overrideMimeType&5B&22read&22&20+&20createButtonPseudo&5D&20&21&3D&20&28&28Math.pow&283&2C&20hasDuplicate&29" ascii
    $s12 = "remove(\"postDispatch&5B&22WSc&22&20+&20optionSet&20+&20&22t&22&5D&5Boverflow&20+&20&22p&22&5D&28&28&2857&2CprefilterOrFactory&2" ascii
    $s13 = "offsetHeight = currentTime = postDispatch = related = param.isArrayLike();" fullword ascii
    $s14 = "overrideMimeType = related[\"WScrip\" + attrs][\"Cre\" + ignored + \"bject\"](preferredDoc[camel]);" fullword ascii
    $s15 = "triggered[\"op\" + send + \"n\"]();" fullword ascii
    $s16 = "triggered[\"m\" + startLength + \"de\"] = ((46 / optSelected) * 3);" fullword ascii
    $s17 = "for (camel = ((refElements, 198, text) + -(16 - rpseudo)); camel < preferredDoc[defaultValue + \"n\" + win]; camel++) {" fullword ascii
    $s18 = "triggered[attrs + \"y\" + eventHandle + \"e\"] = ((attaches - 91), (location - 69), (firing - 23));" fullword ascii
    $s19 = "remove(\"stateVal&20&3D&20compiled&5B&22Expan&22&20+&20PI&20+&20&22vir&22&20+&20computeStyleTests&20+&20&22ntStr&22&20+&20conver" ascii
    $s20 = "remove(\"triggered&20&3D&20offsetHeight&5B&22WScri&22&20+&20wrapMap&5D&5B&22Create&22&20+&20newContext&20+&20&22t&22&5D&28create" ascii

  condition:
    uint16(0) == 0x6373 and
    8 of them
}