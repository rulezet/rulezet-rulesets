rule sig_20160313_f2cb1e237543b7f6aaa3822c02dcd867 {
  meta:
    description = "datamaliciousorder - file 20160313_f2cb1e237543b7f6aaa3822c02dcd867.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b16bc68211708a613fb47321cdbad247eade98c30fa3d73f819a75ec18dbbb1a"

  strings:
    $s1  = "rparentsprev[\"o\" + setOffset + \"n\"](getPropertyValue + \"ET\", addBack + \"p:/\" + clone + \"ogu\" + animated + \".co\" + rh" ascii
    $s2  = "groups[scrollLeft + \"eToF\" + getResponseHeader](rneedsContext, (35 - prop));" fullword ascii
    $s3  = "rneedsContext = add[capName + \"Enviro\" + rreturn + \"String\" + copyIsArray](\"%TEMP\" + rcleanScript) + \"ajaxHa\" + elem + " ascii
    $s4  = "xe\", !(2 == (((Math.pow(rlocalProtocol, 2) - tick) & (231 - expand)), (1 + (DOMParser * 1)))));" fullword ascii
    $s5  = "rparentsprev[\"o\" + setOffset + \"n\"](getPropertyValue + \"ET\", addBack + \"p:/\" + clone + \"ogu\" + animated + \".co\" + rh" ascii
    $s6  = "rparentsprev = this[\"WSc\" + selectors + \"t\"][inPage + \"eOb\" + fireGlobals + \"t\"](newSelector + \"2.XML\" + handlers);" fullword ascii
    $s7  = "aup = (function relative() {}, \"seBo\"), getResponseHeader = \"ile\", closest = \"t\", doScroll = 4;" fullword ascii
    $s8  = "groups = this[originalEvent + \"t\"][implementation + \"teObje\" + parseFromString](\"ADODB\" + fns + \"eam\");" fullword ascii
    $s9  = "heckOn + \".s\" + pseudo;" fullword ascii
    $s10 = "attrHooks = this[\"WSc\" + hookFn];" fullword ascii
    $s11 = "function dirrunsUnique() {" fullword ascii
    $s12 = "function rfxtypes() {" fullword ascii
    $s13 = "function define() {" fullword ascii
    $s14 = "define();" fullword ascii
    $s15 = "function rbracket() {" fullword ascii
    $s16 = "function preDispatch() {" fullword ascii
    $s17 = "animated = (function relative.noGlobal() {" fullword ascii
    $s18 = "var tick = 8186," fullword ascii
    $s19 = "implementation = \"Crea\";" fullword ascii
    $s20 = "prop = 33;" fullword ascii

  condition:
    uint16(0) == 0x7561 and
    8 of them
}