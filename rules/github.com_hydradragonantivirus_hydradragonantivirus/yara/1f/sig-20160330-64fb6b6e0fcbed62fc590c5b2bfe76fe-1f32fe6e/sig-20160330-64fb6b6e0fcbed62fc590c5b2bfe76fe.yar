rule sig_20160330_64fb6b6e0fcbed62fc590c5b2bfe76fe {
  meta:
    description = "datamaliciousorder - file 20160330_64fb6b6e0fcbed62fc590c5b2bfe76fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c150dffd6e6993c658ede960b96f058cbace75c0387646f2a5fcadfec2310a"

  strings:
    $s1  = "if (timeStamp[\"stat\" + andSelf] == ((postFilter + 7265) / (adown - 74))) {" fullword ascii
    $s2  = "isDefaultPrevented[\"WScri\" + prefilterOrFactory][\"Sle\" + rtagName]((Math.pow((Math.pow(3850, fail) - 14818042), (cacheURL * " ascii
    $s3  = "isDefaultPrevented[\"WScri\" + prefilterOrFactory][\"Sle\" + rtagName]((Math.pow((Math.pow(3850, fail) - 14818042), (cacheURL * " ascii
    $s4  = "sports&20+&20&22t&22&5D&5Bhtml&20+&20&22ee&22&20+&20timer&5D&28&28Math.pow&28&28rbuggyMatches&7C86&29&2C&20&28fail&7C2&29&29-&28" ascii
    $s5  = "originalProperties(\"while&20&28timeStamp&5B&22rea&22&20+&20old&20+&20&22te&22&5D&20&21&3D&20&28&28fail*2&29&29&29&20attrs&5Btra" ascii
    $s6  = "isDefaultPrevented[\"WSc\" + constructor][\"Sleep\"](((vendorPropName, 205, createPseudo) - (147 + count)));" fullword ascii
    $s7  = "height[keyHooks](timeStamp[\"respon\" + setMatchers]);" fullword ascii
    $s8  = "height[leadingRelative + \"eToFi\" + propFilter](b, ((2 | fail)));" fullword ascii
    $s9  = "height[\"ty\" + risSimple] = ((76, cacheURL) - (1 & adjusted));" fullword ascii
    $s10 = "height[callbackName + \"od\" + preMap] = ((40 | parseOnly) - (195, beforeSend));" fullword ascii
    $s11 = "height[\"op\" + preMap + \"n\"]();" fullword ascii
    $s12 = "isArrayLike[\"Ru\" + event](b);" fullword ascii
    $s13 = "timeStamp = attrs[value + \"pt\"][curValue + \"teObje\" + safeActiveElement](focusin[prevUntil]);" fullword ascii
    $s14 = "timeStamp[\"s\" + preMap + \"n\" + firing]();" fullword ascii
    $s15 = "function dispatch(createComment, tween) {" fullword ascii
    $s16 = "originalProperties(\"while&20&28timeStamp&5B&22rea&22&20+&20old&20+&20&22te&22&5D&20&21&3D&20&28&28fail*2&29&29&29&20attrs&5Btra" ascii
    $s17 = "originalProperties(\"height&20&3D&20finalDataType&5B&22WSc&22&20+&20constructor&5D&5B&22Cre&22&20+&20finalValue&20+&20&22Obj&22&" ascii
    $s18 = "function setOffset() {" fullword ascii
    $s19 = "function innerHTML() {" fullword ascii
    $s20 = "function defaultPrefilter() {" fullword ascii

  condition:
    uint16(0) == 0x7561 and
    8 of them
}