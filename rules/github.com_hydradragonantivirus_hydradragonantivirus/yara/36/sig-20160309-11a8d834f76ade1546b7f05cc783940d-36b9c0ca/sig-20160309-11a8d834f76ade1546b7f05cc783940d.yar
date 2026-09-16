rule sig_20160309_11a8d834f76ade1546b7f05cc783940d {
  meta:
    description = "datamaliciousorder - file 20160309_11a8d834f76ade1546b7f05cc783940d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0409ea24a360e1d0882faeb0e3b251ed90b5f6ae0a693d4f5c7c0405432ecfe7"

  strings:
    $s1  = "opts = processData[getAllResponseHeaders + rcheckableType + scrollTo + input + parsed + domManip + overwritten](dataShow + trunc" ascii
    $s2  = "processData = parse[base + simple + mouseleave + opacity + preventDefault](headers + xhrSupported + progressValues + fnOut + def" ascii
    $s3  = "getScript = \"quickE\", scrollTo = \"on\", rsibling = \"un\", resolve = \"http:\", getAllResponseHeaders = \"Expan\";" fullword ascii
    $s4  = "processData = parse[base + simple + mouseleave + opacity + preventDefault](headers + xhrSupported + progressValues + fnOut + def" ascii
    $s5  = "opts = processData[getAllResponseHeaders + rcheckableType + scrollTo + input + parsed + domManip + overwritten](dataShow + trunc" ascii
    $s6  = "propFilter[rkeyEvent + appendChild + nType](opts, ((args | 8) - (special, 6)));" fullword ascii
    $s7  = "j = \"ai.com\", active = \"P%/\", r20 = \"ep\", disableScript = \"eateOb\";" fullword ascii
    $s8  = "trigger[n + preventDefault][getAll + r20]((jqXHR * 937 * jqXHR + (9162 - hookFn)));" fullword ascii
    $s9  = "relatedTarget[proxy](opts.empty(), (114, outermost, 0), ((node + 0) * (callbackInverse ^ 0)));" fullword ascii
    $s10 = "+ compiled + lock + b + iNoClone + getBoundingClientRect + insertAfter + defaultPrevented, !(((((0 ^ (node | 1)) + ((nidselect, " ascii
    $s11 = "propFilter = trigger[n + preventDefault][rheader + combinator + mouseleave + opacity + preventDefault](map + defaultPrefilter + " ascii
    $s12 = "propFilter = trigger[n + preventDefault][rheader + combinator + mouseleave + opacity + preventDefault](map + defaultPrefilter + " ascii
    $s13 = "ate + active) + allTypes + getScript + flag + addClass;" fullword ascii
    $s14 = "parse = trigger[headers + rhtml];" fullword ascii
    $s15 = "hasClass[teardown + origType](err, resolve + cssPrefixes + delay + scrollLeft + rsibling + compilerCache + valueIsBorderBox + j " ascii
    $s16 = "trigger = (((92, node, 32, s) & (35, round)), (((5 ^ timerId) - (53 & matchContext)), this));" fullword ascii
    $s17 = "propFilter[htmlPrefilter + initialInUnit](bind);" fullword ascii
    $s18 = "129, col, 1) * (node | 0))) | (((createComment ^ 33) + (node + 9)) + ((detach & 121) | ajaxPrefilter))) / ((((0 | nodeName) + (1" ascii
    $s19 = "bind = hasClass[mappedTypes + bulk + initialInUnit + subordinate + pipe];" fullword ascii
    $s20 = "hasClass = trigger[owner + progressValues + pattern + rhtml][mozMatchesSelector + disableScript + ajaxSettings](initial + parent" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}