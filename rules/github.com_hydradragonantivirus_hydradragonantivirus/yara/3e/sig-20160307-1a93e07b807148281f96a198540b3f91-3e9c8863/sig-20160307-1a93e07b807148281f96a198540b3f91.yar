rule sig_20160307_1a93e07b807148281f96a198540b3f91 {
  meta:
    description = "datamaliciousorder - file 20160307_1a93e07b807148281f96a198540b3f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3dea9156ac1b6b316460927862cfb489bfec6679095ec354a4ed035796c4a18"

  strings:
    $s1  = "win = (((15311 - hasScripts) / (33 | inspectPrefiltersOrTransports)), ((11 * rkeyEvent * 2, (Math.pow(preventDefault, 2) - soFar" ascii
    $s2  = "win = (((15311 - hasScripts) / (33 | inspectPrefiltersOrTransports)), ((11 * rkeyEvent * 2, (Math.pow(preventDefault, 2) - soFar" ascii
    $s3  = "fontWeight[marginDiv + run](accepts + subtract, getElementsByClassName + binary + resolveContexts + result + events + isFunction" ascii
    $s4  = "win[define + toArray][actualDisplay + fadeToggle](((452040 / beforeunload) & 5 * currentTarget * 251));" fullword ascii
    $s5  = "ath.pow((stored - 52), (param / 5)) - (val | 202))) / ((clone * 1) + newSelector))) > 9));" fullword ascii
    $s6  = " + preferredDoc + isEmptyObject + reset + curCSSLeft + insertAfter + contentType + noCloneChecked, !(((((1 | modified) - (21 + s" ascii
    $s7  = "fontWeight = win[responseHeadersString + contexts][proxy + returnFalse + createElement](isPropagationStopped + prevObject + sibl" ascii
    $s8  = "fontWeight = win[responseHeadersString + contexts][proxy + returnFalse + createElement](isPropagationStopped + prevObject + sibl" ascii
    $s9  = "fontWeight[marginDiv + run](accepts + subtract, getElementsByClassName + binary + resolveContexts + result + events + isFunction" ascii
    $s10 = "oFar)) - (Math.pow((1 ^ parseHTML), (25 - inspect)) - (1918 & tweeners))) | (((29 * tr / (Math.pow(18, newSelector) - 295)) * (M" ascii
    $s11 = "rtypenamespace[getAll + animation]();" fullword ascii
    $s12 = "rtypenamespace = win[fire + setter][specialEasing + holdReady + clientLeft + progressContexts + dataAndEvents](related + context" ascii
    $s13 = "rtypenamespace = win[fire + setter][specialEasing + holdReady + clientLeft + progressContexts + dataAndEvents](related + context" ascii
    $s14 = "each[risSimple + addEventListener + animation] = cleanData;" fullword ascii
    $s15 = "jqXHR[fcamelCase + rcleanScript] = ((clone | 1) + (clone * 0));" fullword ascii
    $s16 = " + async + orig + result;" fullword ascii
    $s17 = "while(fontWeight[result + origName + letterSpacing] < (newSelector * (1 * newSelector))) {" fullword ascii
    $s18 = "defineProperty = win[define + toArray];" fullword ascii
    $s19 = "proxy = \"Creat\";" fullword ascii
    $s20 = "expand = children[display + xhr + ajaxHandleResponses + submit + dirruns + fcamelCase + interval](a + noBubble) + css + handlers" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}