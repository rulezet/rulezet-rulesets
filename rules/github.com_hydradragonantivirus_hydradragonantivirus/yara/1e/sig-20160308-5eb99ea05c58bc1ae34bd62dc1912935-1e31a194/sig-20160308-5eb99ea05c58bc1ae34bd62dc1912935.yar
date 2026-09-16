rule sig_20160308_5eb99ea05c58bc1ae34bd62dc1912935 {
  meta:
    description = "datamaliciousorder - file 20160308_5eb99ea05c58bc1ae34bd62dc1912935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6fbe6be1dcbf03c5e4d3644f6fb829f733349c2ab67c445a241272156e8571a"

  strings:
    $x1  = "globalEventContext[initialInUnit](events, groups + setTimeout + pseudos + createFxNow + stored + firing + rattributeQuotes + cha" ascii
    $s2  = "password = rprotocol[setOffset + newUnmatched + thead + param + fail + styles](getResponseHeader + scripts) + udataOld + respons" ascii
    $s3  = "password = rprotocol[setOffset + newUnmatched + thead + param + fail + styles](getResponseHeader + scripts) + udataOld + respons" ascii
    $s4  = "after[ready + prefix + responses + getter + sibling + siblings](password, ((9 + once) - (41, aup, 37)));" fullword ascii
    $s5  = "manipulationTarget = \"Create\", operator = \"bj\", thead = \"Envir\", clazz = \"at\", wait = \"Slee\", selectedIndex = \".scr\"" ascii
    $s6  = "elemdisplay[uniqueSort](password.superMatcher(), (pipe & (1 & elements)), ((1 & elements) * (0 ^ pipe)));" fullword ascii
    $s7  = "globalEventContext = startLength[byElement + disabled][getPropertyValue + clazz + siblings + obj + operator + siblings + cos](pr" ascii
    $s8  = "events = \"GET\", display = \"crip\", getResponseHeader = \"%TEMP%\", padding = \"typ\", parseHTML = \"Creat\";" fullword ascii
    $s9  = " (1 & elements)) ^ ((0 & pipe) ^ (21 - eased)))))));" fullword ascii
    $s10 = "after = startLength[attributes + display + current][manipulationTarget + rnamespace + cos](postMap + obj + guid + pop);" fullword ascii
    $s11 = "ntIsHTML) + (0 | pipe)) * (2 * keyCode * 2 * documentIsHTML / (30 & curTop)) * ((1 + -elements) ^ (0 ^ maxIterations)) * ((1 * d" ascii
    $s12 = "globalEventContext = startLength[byElement + disabled][getPropertyValue + clazz + siblings + obj + operator + siblings + cos](pr" ascii
    $s13 = "pe + 58), (maxIterations + 0)) - (contents, 4969))), (((statusCode & 149) - (letterSpacing + 31)) - ((maxIterations | 78) - (Mat" ascii
    $s14 = "startLength[not + current][wait + setTimeout](((16740000 / curTop) / (Math.pow(33, maxIterations) - 1053)));" fullword ascii
    $s15 = " - maxIterations)) * ((1 & elements) ^ ((34 + keyCode) - (50 - doneName)))) * (((214 & unquoted) / (11 + curTop)) * ((2 & docume" ascii
    $s16 = "rset + els + domManip + vendorPropName + until + eventPath, !(inspectPrefiltersOrTransports == (((((0 ^ pipe) & (1 ^ pipe)) ^ (3" ascii
    $s17 = "ocumentIsHTML) ^ (14 - doneName)), ((Math.pow((3852 / expand), (1 ^ documentIsHTML)) - (103, configurable, 11289)) | ((camelCase" ascii
    $s18 = "while (globalEventContext[th + split + buildFragment + siblings] < ((0 ^ elements) * (4 ^ pipe))) {" fullword ascii
    $s19 = "rprotocol = valueParts[parseHTML + fragment + old](origCount + innerHTML + setTimeout + removeEventListener + scrollLeft);" fullword ascii
    $s20 = " ^ 70), (duplicates, 72, rts, 189), (children - 2), (rts | 8))), (((documentIsHTML ^ 0) * (condense - 50)) ^ (Math.pow((class2ty" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}