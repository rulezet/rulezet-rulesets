rule sig_20160308_d46078905fe06f9da96eac022a2daba7 {
  meta:
    description = "datamaliciousorder - file 20160308_d46078905fe06f9da96eac022a2daba7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "debf6956e0b6201702d0a9cc10357c2b80757936cd8b86ea74d60d03231dc13f"

  strings:
    $s1  = "seekingTransport = targets[optgroup + manipulationTarget + lastChild](iNoClone + fired + exports + mozMatchesSelector);" fullword ascii
    $s2  = "startLength[getComputedStyle + ret](animated, uniqueSort + collection + insertAfter + rtypenamespace + hasOwnProperty + response" ascii
    $s3  = "targets = relative[filter + maxWidth];" fullword ascii
    $s4  = "+ (Math.pow(serialize, 2) - getPropertyValue)), (1 * (toggleClass))))) == (((((3584 | curTop) / (7 + send)) ^ ((454 - checkDispl" ascii
    $s5  = "startLength[getComputedStyle + ret](animated, uniqueSort + collection + insertAfter + rtypenamespace + hasOwnProperty + response" ascii
    $s6  = "relative[iNoClone + fired][rwhitespace + input + v](2 * (Math.pow(startTime, 2) - clearCloneStyle) * (1 | clearCloneStyle) * (1 " ascii
    $s7  = "relative[iNoClone + fired][rwhitespace + input + v](2 * (Math.pow(startTime, 2) - clearCloneStyle) * (1 | clearCloneStyle) * (1 " ascii
    $s8  = " - rhtml) & (121 / bool)))) - (((112308 ^ interval) / (4 * reliableMarginRight + 1)) | (Math.pow((unshift - 93), (sel - 17)) - (" ascii
    $s9  = "radio - 131287)))), (((Math.pow((propFilter - 218), (clearCloneStyle / 2)) - (owner & 130287)) - (reliableMarginRight * 5 * reli" ascii
    $s10 = "Type + setAttribute + register + risSimple + argument + getAll, !(((((toggleClass ^ 0) + ((removeProp - 35) ^ (toggleClass - 0))" ascii
    $s11 = "startLength = relative[stop + contexts + scrollTo][teardown + pattern + udataOld](xhrFields + contentDocument + _default + empty" ascii
    $s12 = "getElementsByClassName[status](reject.groups(), ((originalEvent, 0) / (locked - 45)), ((settings / 2) | (toggleClass + -1)));" fullword ascii
    $s13 = "unmatched[realStringObj + hide + responseHeaders]();" fullword ascii
    $s14 = "startLength = relative[stop + contexts + scrollTo][teardown + pattern + udataOld](xhrFields + contentDocument + _default + empty" ascii
    $s15 = "reject = seekingTransport[overwritten + content + original + rdashAlpha + speed + setOffset](rtrim + rejectWith) + oldCache + cl" ascii
    $s16 = "reject = seekingTransport[overwritten + content + original + rdashAlpha + speed + setOffset](rtrim + rejectWith) + oldCache + cl" ascii
    $s17 = "- 9460)), ((box + 9) / (blur ^ 3))) - (fireGlobals - 505))) + ((((settings & 1) | (ajaxPrefilter, 1)) ^ ((newSelector, 60), (tog" ascii
    $s18 = "status = bindType + map;" fullword ascii
    $s19 = "(17 - bool) | (142 ^ destElements))) - (Math.pow((Math.pow((15 & duplicates), (24 / blur)) - (Math.pow(98, reliableMarginRight) " ascii
    $s20 = "setAttribute = \"pp.u\", rparentsprev = \".scr\", propFilter = 524, handle = \"p\";" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}