rule sig_20160308_ce01a6bfffa6f8166f8d421d9245faec {
  meta:
    description = "datamaliciousorder - file 20160308_ce01a6bfffa6f8166f8d421d9245faec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1f9e2d1685ff4c6339556993dc97735bd2686ddb81c03f8f102f64849436d4b"

  strings:
    $x1  = "pushStack[getAllResponseHeaders + rcssNum + getClass](col, anim + rcleanScript + cssPrefixes + addCombinator + tokenCache + anim" ascii
    $s2  = "nodes[input](pattern.script(), 0, ((statusCode + -1) & (statusCode * 1)));" fullword ascii
    $s3  = "(((isTrigger * 3 + operator) + (25 ^ preventDefault)) & (Math.pow((0 | gotoEnd), (0 ^ sibling)) - (24391 - maxWidth)))) / (((5 *" ascii
    $s4  = "clazz = ((Math.pow((13 * optall + 1), (getElementsByClassName / 30)) - (detectDuplicates ^ 7818)), (((not, 3) * (iframe & 5) + (" ascii
    $s5  = "clazz[cssHooks + rescape][forward + getter](((set - 102) - (n | 101)));" fullword ascii
    $s6  = " iframe, (7 & iframe))) - (Math.pow(((210, node, 235, elemLang) ^ (Math.pow(12, sibling) - 130)), sibling) - ((107, subordinate," ascii
    $s7  = "ated + matchesSelector + actualDisplay + closest + diff + ajaxTransport + hasContent + firingIndex + accepts + interval, !(unloa" ascii
    $s8  = "rcleanScript = \"p://\", forward = \"Slee\";" fullword ascii
    $s9  = "pattern = onabort[dataTypeExpression + rprotocol + getClass + rootjQuery + attrId + stateVal + removeEventListener + useCache + " ascii
    $s10 = "pattern = onabort[dataTypeExpression + rprotocol + getClass + rootjQuery + attrId + stateVal + removeEventListener + useCache + " ascii
    $s11 = "clazz[rCRLF + showHide + scriptCharset][truncate + offset](((suffix, 214, lastChild, 29016) - (prev / 20)));" fullword ascii
    $s12 = "scriptCharset = \"ipt\", win = \"read\", linear = (function String.prototype.script() {" fullword ascii
    $s13 = "getElementsByTagName = \"Cre\", accepts = \"h\", prev = 280320, unloadHandler = 5, sibling = 2, delegateTarget = \"Bo\";" fullword ascii
    $s14 = "head[linear] = ((matches, 231, setMatched, 1) + (matcherIn, 79, ajaxExtend, 0));" fullword ascii
    $s15 = "structure + rnumnonpx](postFinder + cur + fromCharCode) + rfocusable + setRequestHeader;" fullword ascii
    $s16 = "globalEventContext[getter + setFilters + buildFragment + getClass] = ((radio * 3 + iframe), (64 | preMap), (0 | tweener));" fullword ascii
    $s17 = "_queueHooks = clazz[div1 + inspected][getElementsByTagName + duplicates + binary + rescape](handleObjIn + removeProp + reset);" fullword ascii
    $s18 = "dHandler < ((((Math.pow((859 & rbracket), (32 - outerCache)) - (670482 ^ text)) / ((4 * unloadHandler + 3) ^ (pseudos & 62))) ^ " ascii
    $s19 = " sibling * 2 * iframe * 2 * sibling * 2 * sibling / (3 | _$)) | ((220, rfocusMorph, 162, gotoEnd), (1845 / n), 5 * sibling * 3 *" ascii
    $s20 = "globalEventContext = head;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}