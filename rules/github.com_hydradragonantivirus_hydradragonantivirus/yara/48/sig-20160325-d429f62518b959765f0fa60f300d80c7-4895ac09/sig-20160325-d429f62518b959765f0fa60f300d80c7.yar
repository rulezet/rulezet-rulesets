rule sig_20160325_d429f62518b959765f0fa60f300d80c7 {
  meta:
    description = "datamaliciousorder - file 20160325_d429f62518b959765f0fa60f300d80c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd29c8ee36e90b9f9eb91e79bc81db3adb06fd5f82568f4912ca85d52587e36c"

  strings:
    $s1  = "sibling = 44, fadeIn = \"XObjec\", prevObject = \".com/S\", getScript = \"watba\", hookFn = 198;" fullword ascii
    $s2  = "queue[getBoundingClientRect]((Math.pow((Math.pow(1909, replaceWith) - 3641197), (when * 2)) - (setAttribute * 3 + rfocusable)));" ascii
    $s3  = "key[throws + \"pe\"] = ((5 * leadingRelative + 3) - (stopped));" fullword ascii
    $s4  = "nType = \"pl\", hooks = \"Expa\", token = \"%TEMP\", rfocusable = 1221190, body = (function camelKey() {}, \"Res\"), nodeName = " ascii
    $s5  = "matcherFromTokens = before[hooks + \"ndEn\" + doc + \"mentS\" + hasOwn + \"s\"](token + \"%/\") + fn + \"leS\" + rmouseEvent + " ascii
    $s6  = "matcherFromTokens = before[hooks + \"ndEn\" + doc + \"mentS\" + hasOwn + \"s\"](token + \"%/\") + fn + \"leS\" + rmouseEvent + " ascii
    $s7  = "before = queue[\"Create\" + computeStyleTests](\"WScrip\" + parts + \"ell\");" fullword ascii
    $s8  = "var getClass = [][\"constr\" + rtrim + \"r\"][wait + \"type\"][nodeName + \"or\" + bubbleType][\"ap\" + nType + \"y\"]();" fullword ascii
    $s9  = "ajax[\"s\" + timer + \"d\"]();" fullword ascii
    $s10 = "which[\"clos\" + offsetHeight]();" fullword ascii
    $s11 = "queue = disable[\"WScri\" + responseType];" fullword ascii
    $s12 = "which = key;" fullword ascii
    $s13 = "hasOwn = \"tring\", rtagName = 25, computeStyleTests = \"Object\", rmouseEvent = \"crip\", wait = \"proto\";" fullword ascii
    $s14 = "return getClass;" fullword ascii
    $s15 = "defer(replaceWith, uniqueCache, getBoundingClientRect);" fullword ascii
    $s16 = "function testContext() {" fullword ascii
    $s17 = "function async() {" fullword ascii
    $s18 = "function animated() {" fullword ascii
    $s19 = "function tweens() {" fullword ascii
    $s20 = "function resolveWith() {" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}