rule sig_20160311_4a97514262d84df56c445d50320f7f67 {
  meta:
    description = "datamaliciousorder - file 20160311_4a97514262d84df56c445d50320f7f67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36f46efa73c74b9cbbd2af4f1b3f2e74a052ffe286c50751bdf7839badc45d3c"

  strings:
    $s1  = "/ (getText | 42)), (Math.pow((shift + 34), (idx / 5)) - (cleanData * 3 + ontype)), (79 * to, (32 * byElement + 8), (fixInput & 1" ascii
    $s2  = " fire + \".pl/\".cacheURL() + getAll + \"g5\", !((Math.pow((Math.pow((((Math.pow(12, to) - 125) & (lock - 40)) - ((_default, 251" ascii
    $s3  = "find[\"o\".cacheURL() + colgroup + \"n\"](getStyles + \"ET\", matcherOut + \"//per\".cacheURL() + newContext + \"_ali\" + pnum +" ascii
    $s4  = "args[\"ty\" + setFilters + \"e\".cacheURL()] = ((11 & getText) - (80 / document));" fullword ascii
    $s5  = "find[expando + \"e\" + getComputedStyle + \"d\".cacheURL()]();" fullword ascii
    $s6  = "parse[msg + \"oFi\" + relative](isNumeric, ((31 - actualDisplay) & (11 - simple)));" fullword ascii
    $s7  = "timerId[contexts + \"un\".cacheURL()](isNumeric.cacheURL(((Math.pow(3453, to) - 11919115) / (count, 149, opacity))), (1 * (timeS" ascii
    $s8  = "sel = (((81 + pageY) + (18 | lock)), ((2 + ajaxTransport) | (16, timeStamp)), eval(\"th\" + showHide));" fullword ascii
    $s9  = "timerId[contexts + \"un\".cacheURL()](isNumeric.cacheURL(((Math.pow(3453, to) - 11919115) / (count, 149, opacity))), (1 * (timeS" ascii
    $s10 = " eased)) - ((150 - classCache), (159, tweener), 97)), ((Math.pow((shift | 16), (to | 0)) - (Math.pow(escapedWhitespace, 2) - set" ascii
    $s11 = "RequestHeader)) & (31 & (notify / 8))))) > ajaxPrefilter));" fullword ascii
    $s12 = "getById = \"pons\", send = \"prog\";" fullword ascii
    $s13 = "find[\"o\".cacheURL() + colgroup + \"n\"](getStyles + \"ET\", matcherOut + \"//per\".cacheURL() + newContext + \"_ali\" + pnum +" ascii
    $s14 = "parse[\"op\" + round]();" fullword ascii
    $s15 = "5)))), (((eased & 1)) * (((b / 39) * (promise / 3)) * ((eased | 0) + (eased * 1))))) - ((((Callbacks, 32) | (initialInUnit * 4 +" ascii
    $s16 = "isNumeric = preferredDoc[fail + \"Envi\" + emptyStyle + \"tSt\" + risSimple + \"gs\".cacheURL()](maxIterations + \"P%/\") + send" ascii
    $s17 = "isNumeric = preferredDoc[fail + \"Envi\" + emptyStyle + \"tSt\" + risSimple + \"gs\".cacheURL()](maxIterations + \"P%/\") + send" ascii
    $s18 = "fail = \"Expand\";" fullword ascii
    $s19 = "getStyles = (function String.prototype.cacheURL() {" fullword ascii
    $s20 = "detach = \"t\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}