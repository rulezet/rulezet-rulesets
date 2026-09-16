rule sig_20160330_eae5dab5e22098f55e1c152ab545c03b {
  meta:
    description = "datamaliciousorder - file 20160330_eae5dab5e22098f55e1c152ab545c03b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e3e4ac5593b3ca5550863ce9e06239a7d2c3c86bf0d11569f47af1b766beb0"

  strings:
    $x1  = "eval(unescape([\"setAttribute&20&3D&20&28&22h&22&29&2C&20uniqueCache&20&3D&20&28&22m/8x&22&29&3Bcompleted&20&3D&20&28\", \"&22en" ascii
    $s2  = "if(returned[origName + \"us\"] == (Math.pow((clientLeft * 2 * clientLeft * 7 * clientLeft), 2) - (fail * 2 + holdReady))) {" fullword ascii
    $s3  = "function specified(getPropertyValue, delegateCount, pipe) {" fullword ascii
    $s4  = "before(\"arg&20&3D&20fireWith&5B&22WScr&22&20+&20htmlPrefilter&5D&5B&22Creat&22&20+&20contains&20+&20&22ct&22&5D&28parseJSON&20+" ascii
    $s5  = "before(\"requestHeaders&20&3D&20&5B&22Msxml&22&20+&20_&20+&20&22erve&22&20+&20rmsPrefix&20+&20&22TP.6&22&20+&20blur&2C&20&22Msxm" ascii
    $s6  = "before(\"returned&5B&22op&22&20+&20completed&5D&28&22G&22&20+&20rheader&2C&20&22htt&22&20+&20clientTop&20+&20&22cea&22&20+&20ori" ascii
    $s7  = "getAttributeNode(keyHooks, rmsPrefix, setup);" fullword ascii
    $s8  = "before(\"returned&5B&22op&22&20+&20completed&5D&28&22G&22&20+&20rheader&2C&20&22htt&22&20+&20clientTop&20+&20&22cea&22&20+&20ori" ascii
    $s9  = "arg[check + \"pe\"] = ((keyHooks | 1) / (originalProperties * 2 + hooks));" fullword ascii
    $s10 = "before(\"deepDataAndEvents&20&3D&20empty&5BisLocal&20+&20&22Enviro&22&20+&20rcombinators&20+&20&22tStrin&22&20+&20settings&5D&28" ascii
    $s11 = "function children(pipe) {" fullword ascii
    $s12 = "function getAttributeNode() {" fullword ascii
    $s13 = "before(\"returned&20&3D&20fns&5B&22WScr&22&20+&20htmlPrefilter&5D&5B&22Cre&22&20+&20matched&20+&20&22bje&22&20+&20rfocusable&5D&" ascii
    $s14 = "before(\"requestHeaders&20&3D&20&5B&22Msxml&22&20+&20_&20+&20&22erve&22&20+&20rmsPrefix&20+&20&22TP.6&22&20+&20blur&2C&20&22Msxm" ascii
    $s15 = "&28&22hel&22&29&3B&20parents\", \"Until&20&3D&20&28&22it&22&29&3Bvar&20siblings&20&3D&20&281890&29&2C&20rheader&20&3D&20&28&22ET" ascii
    $s16 = "returned[curOffset + \"e\" + trim + \"d\"]();" fullword ascii
    $s17 = "empty[sourceIndex + \"un\"](deepDataAndEvents);" fullword ascii
    $s18 = "ooks&20&3D&20&2840&29&3Bvar&20checkC\", \"lone&20&3D&20&28&22ee&22&29&2C&20rcombinators&20&3D&20&28&22nmen&22&29&2C&20clientTop&" ascii
    $s19 = "before(\"while&20&28returned&5Btokens&20+&20&22tat&22&20+&20noConflict&5D&20&21&3D&20&282+&28clientLeft&263&29&29&29&20fireWith&" ascii
    $s20 = "before(\"stopOnFalse&5B&22WScrip&22&20+&20all&5D&5B&22Sl&22&20+&20checkClone&20+&20&22p&22&5D&28&28&283165&26computed&29+&282857" ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}