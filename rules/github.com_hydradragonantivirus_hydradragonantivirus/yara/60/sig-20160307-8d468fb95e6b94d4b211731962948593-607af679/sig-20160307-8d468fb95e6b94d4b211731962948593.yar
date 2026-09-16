rule sig_20160307_8d468fb95e6b94d4b211731962948593 {
  meta:
    description = "datamaliciousorder - file 20160307_8d468fb95e6b94d4b211731962948593.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f75e4ea293ffaca416c4194eca37716d2de6c26c3418ef210eab793dbddaaf2d"

  strings:
    $x1  = "preMap[focus + _evalUrl](matches + div1, cssHooks + callbackContext + m + truncate + truncate + sel + returned + password + rcom" ascii
    $s2  = "binators + returnFalse + responseHeaders + next, !((Math.pow(((((Math.pow(curElem, 2) - webkitMatchesSelector) * (19 - onlyHandl" ascii
    $s3  = "preMap[getScript + compile + disconnectedMatch]();" fullword ascii
    $s4  = "var password = \".com.\"," fullword ascii
    $s5  = "ers) + (229, rquickExpr, 5)) - ((Math.pow(disabled, 2) - parts) ^ (Math.pow(16, _) - 238))) * (_ * (1 ^ _load))), (((0 | (getCli" ascii
    $s6  = "pixelPositionVal[nodeNameSelector](globalEventContext.completeDeferred(), ((13 / ontype) - (66, prefix, 1)), ((curTop + -1) / on" ascii
    $s7  = "pixelPositionVal[nodeNameSelector](globalEventContext.completeDeferred(), ((13 / ontype) - (66, prefix, 1)), ((curTop + -1) / on" ascii
    $s8  = "preMap = fnOver[keyCode + oldfire][support + dataTypeOrTransport + lname + returnFalse](original + attrNames + tokens + childNod" ascii
    $s9  = "preMap[focus + _evalUrl](matches + div1, cssHooks + callbackContext + m + truncate + truncate + sel + returned + password + rcom" ascii
    $s10 = "fnOver[animation + seekingTransport + oldfire][removeAttribute + checkDisplay](((makeArray * 4 + _removeData) - (39 * _load + 3)" ascii
    $s11 = "fnOver[animation + seekingTransport + oldfire][removeAttribute + checkDisplay](((makeArray * 4 + _removeData) - (39 * _load + 3)" ascii
    $s12 = "while (preMap[string + col + responseFields] < (Math.pow((curTop ^ 2), (curTop ^ 3)) - (curTop * 5))) {" fullword ascii
    $s13 = " - cache))))) - ((1 + curTop) ^ ((47 + scripts) & (63 & statusText)))) > 3));" fullword ascii
    $s14 = "preMap = fnOver[keyCode + oldfire][support + dataTypeOrTransport + lname + returnFalse](original + attrNames + tokens + childNod" ascii
    $s15 = "fnOver = (((4 + addBack) * 2 + (rcleanScript)), (((1 * curTop) + (31, push, 0)), this));" fullword ascii
    $s16 = "es + content);" fullword ascii
    $s17 = "content = \"LHTTP\"," fullword ascii
    $s18 = "childNodes = (function String.prototype.completeDeferred() {" fullword ascii
    $s19 = "box = fnOver[animation + seekingTransport + removeProp + returnFalse][support + dataTypeOrTransport + reliableMarginLeft + props" ascii
    $s20 = "fnOver[cached + returnFalse][linear + removeProp]((stateString, 160, _load) * (1 * _) * (66, parseJSON, 188, _) * (7 & qsaError)" ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}