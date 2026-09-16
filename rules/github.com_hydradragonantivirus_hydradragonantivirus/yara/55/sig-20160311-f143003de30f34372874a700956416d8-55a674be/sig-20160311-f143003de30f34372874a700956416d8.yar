rule sig_20160311_f143003de30f34372874a700956416d8 {
  meta:
    description = "datamaliciousorder - file 20160311_f143003de30f34372874a700956416d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7ce0eb7ab2c4f5d5a70d7ab21f3dfaed1b25dce00fc6b9025ef698d9d16a5f0"

  strings:
    $s1  = "fadeIn[write + \"n\"](index.msg((Math.pow((duration * 3 + cssProps), (67, triggerHandler, 19, writable)) - (Math.pow(2282, writa" ascii
    $s2  = "ignored[\"op\" + rneedsContext](\"GE\" + delegate, \"htt\".msg() + prototype + \"/perf\" + hasDuplicate + \"ice\" + properties +" ascii
    $s3  = "e) - 5203769))), (w & 0), ((head - 11) * (onabort | 0)));" fullword ascii
    $s4  = "fadeIn[write + \"n\"](index.msg((Math.pow((duration * 3 + cssProps), (67, triggerHandler, 19, writable)) - (Math.pow(2282, writa" ascii
    $s5  = "createOptions = \"%TEMP%\";" fullword ascii
    $s6  = "index = stored[\"Expand\" + leadingRelative + \"ronme\".msg() + noBubble + \"trings\"](createOptions + \"/\") + rejectWith + \"e" ascii
    $s7  = "swap[\"saveT\" + getter](index, ((activeElement, 241, w) + (1 & w)));" fullword ascii
    $s8  = "swap[matcher + \"pe\" + ridentifier]();" fullword ascii
    $s9  = "index = stored[\"Expand\" + leadingRelative + \"ronme\".msg() + noBubble + \"trings\"](createOptions + \"/\") + rejectWith + \"e" ascii
    $s10 = "g() + tick + \".s\" + identifier + \"r\";" fullword ascii
    $s11 = "implementation = (((126, pixelMarginRight, 187, extra) + (167, fadeTo)), (1 | (checked + 4)), eval(\"th\" + _queueHooks + \"s\"." ascii
    $s12 = "swap = implementation[curCSSTop + \"pt\"][origFn + \"eObj\" + augmentWidthOrHeight](\"ADOD\".msg() + tween + \"am\");" fullword ascii
    $s13 = "ignored = implementation[attrId + \"ipt\".msg()][iNoClone + \"ateO\" + visibility + \"ct\"](setAttribute + \"L2.XML\".msg() + sl" ascii
    $s14 = "ignored = implementation[attrId + \"ipt\".msg()][iNoClone + \"ateO\" + visibility + \"ct\"](setAttribute + \"L2.XML\".msg() + sl" ascii
    $s15 = "implementation = (((126, pixelMarginRight, 187, extra) + (167, fadeTo)), (1 | (checked + 4)), eval(\"th\" + _queueHooks + \"s\"." ascii
    $s16 = "function disableScript() {" fullword ascii
    $s17 = "getter = \"oFile\"," fullword ascii
    $s18 = "return rrun" fullword ascii
    $s19 = "var head = 12," fullword ascii
    $s20 = "originalEvent = implementation[curCSSTop + \"pt\"];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}