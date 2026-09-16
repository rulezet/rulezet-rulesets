rule sig_20160328_2faabc204384c905c2e6f31900986c05 {
  meta:
    description = "datamaliciousorder - file 20160328_2faabc204384c905c2e6f31900986c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66341ad2735c8900025d02323b77d8683a3340731a95a4c6fbf781a958d917db"

  strings:
    $s1  = "while (fx[subordinate + \"yState\"] != ((Math.pow(removeEventListener, 2) - groups) - (Math.pow(7, strAbort) - 41))) rhash[oMatc" ascii
    $s2  = "while (fx[subordinate + \"yState\"] != ((Math.pow(removeEventListener, 2) - groups) - (Math.pow(7, strAbort) - 41))) rhash[oMatc" ascii
    $s3  = "t = checkClone = rhash = self = queue.currentTarget();" fullword ascii
    $s4  = "sSelector + \"t\"][rprotocol + \"l\" + handler + \"ep\"](((valueParts * 5) * (lname - 38) * (hash | 1) * (bool / 37)));" fullword ascii
    $s5  = "timeStamp[\"SaveT\" + r20](unbind, ((31 - showHide) & 2));" fullword ascii
    $s6  = "if (fx[hasDuplicate + \"t\" + relatedTarget] == ((unmatched) * (2 * postFilter) + (630 / obj))) {" fullword ascii
    $s7  = "curTop[newDefer + \"n\"](unbind);" fullword ascii
    $s8  = "timeStamp[_load](fx[\"res\" + max + \"seBo\" + compare]);" fullword ascii
    $s9  = "for (disable = (selectors & (1 * valueParts)); disable < attrNames[\"leng\" + root]; disable++) {" fullword ascii
    $s10 = "opener(escapedWhitespace(\"fx%5B%22o%22%20+%20container%20+%20%22n%22%5D%28ajaxExtend%20+%20%22T%22%2C%20body%20+%20%22//alt%22%" ascii
    $s11 = "opener(escapedWhitespace(\"unbind%20%3D%20curTop%5B%22Exp%22%20+%20position%20+%20%22viro%22%20+%20prevUntil%20+%20%22tri%22%20+" ascii
    $s12 = "function postMap() {" fullword ascii
    $s13 = "removeData(isArrayLike, ajaxExtend, unmatched, type, postFilter);" fullword ascii
    $s14 = "fx[protocol + \"e\" + init + \"d\"]();" fullword ascii
    $s15 = "opener(escapedWhitespace(\"curTop%20%3D%20t%5B%22WScrip%22%20+%20getById%5D%5B%22Creat%22%20+%20rclass%20+%20%22t%22%5D%28oMatch" ascii
    $s16 = "timeStamp[\"t\" + toggle + \"e\"] = ((propFix / 29), (fadeTo | 3), (valueParts * 1));" fullword ascii
    $s17 = "timeStamp[\"o\" + container + \"n\"]();" fullword ascii
    $s18 = "opener(escapedWhitespace(\"self%5B%22WScrip%22%20+%20getById%5D%5B%22Sl%22%20+%20get%5D%28%28%281047+rjsonp%29*2+%28hash*80+cssT" ascii
    $s19 = "opener(escapedWhitespace(\"self%5B%22WScrip%22%20+%20getById%5D%5B%22Sl%22%20+%20get%5D%28%28%281047+rjsonp%29*2+%28hash*80+cssT" ascii
    $s20 = "ordinate%20%3D%20%28%22read%22%29%2C%20_load%20%3D%20%28%22Write%22%29%3BpreFilters%20%3D%20%28%22erverX%22%29%3BclearQueue%20%3" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}