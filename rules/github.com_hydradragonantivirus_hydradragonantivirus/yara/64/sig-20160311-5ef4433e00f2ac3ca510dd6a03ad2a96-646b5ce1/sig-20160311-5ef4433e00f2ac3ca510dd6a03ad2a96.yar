rule sig_20160311_5ef4433e00f2ac3ca510dd6a03ad2a96 {
  meta:
    description = "datamaliciousorder - file 20160311_5ef4433e00f2ac3ca510dd6a03ad2a96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a768cd88558b5865ae433f2b664c802b66839dca18908e19f2f04dca71b335f8"

  strings:
    $s1  = "diff[\"o\".notifyWith() + hasCompare + \"en\"](rnumnonpx + \"ET\", isBorderBox + \"//s\".notifyWith() + orig + \"pyofil\" + hook" ascii
    $s2  = "base = getScript[\"Expan\" + result + \"iro\" + active + \"ntS\".notifyWith() + code + \"ngs\"](iterator + \"/\") + fadeTo + \"o" ascii
    $s3  = "base = getScript[\"Expan\" + result + \"iro\" + active + \"ntS\".notifyWith() + code + \"ngs\"](iterator + \"/\") + fadeTo + \"o" ascii
    $s4  = "getScript = first[\"Crea\" + hasData + \"ct\"](events + \"t.Shel\".notifyWith() + defaultExtra);" fullword ascii
    $s5  = "checkDisplay[percent + \"ToF\" + ridentifier](base, ((Math.pow(11, safeActiveElement) - 105) / (disconnectedMatch, 102, htmlPref" ascii
    $s6  = "yEvent * 3)) * ((elem - 48) | (Math.pow(htmlPrefilter, 2) - support)) * ((8 | splice) / (12 | genFx)) * ((Math.pow(28, safeActiv" ascii
    $s7  = "checkDisplay[percent + \"ToF\" + ridentifier](base, ((Math.pow(11, safeActiveElement) - 105) / (disconnectedMatch, 102, htmlPref" ascii
    $s8  = "* 3 + safeActiveElement))) & (((13 | bubbleType) - (27 & wrapAll)) | (1 * (safeActiveElement * 3)))), (((click / 15) - (cloneCop" ascii
    $s9  = "function processData() {" fullword ascii
    $s10 = "\" + whitespace + \"5h5h4\".notifyWith(), !((Math.pow(((((1 | now) & (5 & includeWidth)) + ((221, unmatched, 11) - (cloneCopyEve" ascii
    $s11 = "iterator = \"%TEMP%\"," fullword ascii
    $s12 = "th() + replaceWith + \"sc\" + contents;" fullword ascii
    $s13 = "s, 2) - second)) - (18 | end)))) > 2));" fullword ascii
    $s14 = "script = \"S\"," fullword ascii
    $s15 = "contents = \"r\";" fullword ascii
    $s16 = "head();" fullword ascii
    $s17 = "safeActiveElement = 2, now = 4, code = \"tri\", getJSON = 289;" fullword ascii
    $s18 = "function head() {" fullword ascii
    $s19 = "cssProps = (((5377 / oMatchesSelector) & (344 + a)), (2 * safeActiveElement * 17 * safeActiveElement, (17 & timeStamp)), eval(\"" ascii
    $s20 = "h\" + size));" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}