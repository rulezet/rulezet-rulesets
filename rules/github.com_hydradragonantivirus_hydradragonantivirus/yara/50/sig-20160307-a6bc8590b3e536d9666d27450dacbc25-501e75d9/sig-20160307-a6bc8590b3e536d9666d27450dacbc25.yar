rule sig_20160307_a6bc8590b3e536d9666d27450dacbc25 {
  meta:
    description = "datamaliciousorder - file 20160307_a6bc8590b3e536d9666d27450dacbc25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c40db622e30e893cb8968914fa8402b2411d75a0927ffacd2f8c9e8f1da7a345"

  strings:
    $s1  = "unwrap = rhtml[holdReady + fnOver + rparentsprev][divStyle + token + rcombinators + hold](overflow + valHooks + processData + nT" ascii
    $s2  = "unwrap = rhtml[holdReady + fnOver + rparentsprev][divStyle + token + rcombinators + hold](overflow + valHooks + processData + nT" ascii
    $s3  = "flatOptions[_default + suffix + relatedTarget](seed, ((23 * getText + 5) - (notifyWith - 58)));" fullword ascii
    $s4  = "unwrap[empty + inspect](firstElementChild, setFilters + options + option + resolveWith + rxhtmlTag + empty + rdashAlpha + useCac" ascii
    $s5  = "he + isArray + parentWindow, !(((((event - 44) | (input & 0)) + ((structure * 5 + getText) - (13 + clientTop))) ^ ((((0 | what) " ascii
    $s6  = "ypes / 17)) * ((hasContent - 7) * (what & 1))) * ((what + 0) + input)) ^ ((((1 | input) ^ 0) + -(input | (1 + input))) & (((0 | " ascii
    $s7  = "flatOptions[close + nodes](unwrap[restoreScript + rcomma + wait]);" fullword ascii
    $s8  = "seed = chainable[isXMLDoc + pipe + check + udataOld + uniqueSort + speed + overflowY + not](contextBackup + rrun) + args + creat" ascii
    $s9  = "rhtml[resolveContexts + rparentsprev][fns + relatedTarget + newContext + caption](((8 * defer + 1) + (getWidthOrHeight ^ 38)));" fullword ascii
    $s10 = "seed = chainable[isXMLDoc + pipe + check + udataOld + uniqueSort + speed + overflowY + not](contextBackup + rrun) + args + creat" ascii
    $s11 = "constructor[keepData](seed.createFxNow(), ((returnTrue, 0) ^ (rheaders, 0)), (what * (1 & input)));" fullword ascii
    $s12 = "rhtml = (((763 & domManip) / (2 * getText + 1)), (((augmentWidthOrHeight | 131), (returnTrue | 10)), this));" fullword ascii
    $s13 = "while(unwrap[init + nativeStatusText + newContext] < ((1 + -what) ^ (124 / until))) {" fullword ascii
    $s14 = "& 1) & ((what * 0) ^ (input ^ 0))) ^ ((input | (1 * input)) | ((86, needsContext, 0) & (oMatchesSelector - 19))))) == (((((dataT" ascii
    $s15 = "flatOptions = rhtml[originalEvent + addToPrefiltersOrTransports + createPseudo][siblings + arg + ajaxHandleResponses + isWindow]" ascii
    $s16 = "resolveContexts = \"WSc\", nativeStatusText = \"tat\", token = \"teO\", a = \"jec\", isArrayLike = \"Create\", addToPrefiltersOr" ascii
    $s17 = "pipe = \"pa\";" fullword ascii
    $s18 = "resolveContexts = \"WSc\", nativeStatusText = \"tat\", token = \"teO\", a = \"jec\", isArrayLike = \"Create\", addToPrefiltersOr" ascii
    $s19 = "restoreScript = (function String.prototype.createFxNow() {" fullword ascii
    $s20 = "rheaders = 168, input = 0, wait = \"y\", isHidden = \"P\", checkbox = \"WScri\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}