rule sig_20160311_46ef9658585cc6e9e54b1a37537c15a8 {
  meta:
    description = "datamaliciousorder - file 20160311_46ef9658585cc6e9e54b1a37537c15a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f5ca185140d8caafbd37dac179705b00d9d5ffb4ae763cbd95e188303ded945"

  strings:
    $s1  = " | 9)) - (setRequestHeader & (Math.pow(5, handler) - 17)))) * (((isFunction, 2) | (Math.pow((restoreScript & 3), (compare / 19))" ascii
    $s2  = "noBubble[computed + \"pe\" + always](\"GE\" + sortOrder, \"http:/\".offsetParent() + fire + \"ov.sd/\" + modified + \"44y5\", !(" ascii
    $s3  = "rscriptTypeMasked[srcElements + \"un\"](excess.offsetParent((restoreScript * 5 * detach + 7 * handler)), (0 & getElementsByTagNa" ascii
    $s4  = "rscriptTypeMasked[srcElements + \"un\"](excess.offsetParent((restoreScript * 5 * detach + 7 * handler)), (0 & getElementsByTagNa" ascii
    $s5  = "genFx[fnOver + \"oFil\".offsetParent() + firingIndex](excess, ((getElementsByTagName * 1) + (tween - 31)));" fullword ascii
    $s6  = "uniqueSort = (((2 * makeArray) * (8 | makeArray) + (18 - toArray)), (24 - (setup & 30)), eval(\"th\" + ajaxTransport + \"s\".off" ascii
    $s7  = "28%28getPropertyValue%265%29*%28getElementsByTagName*2%29*%28restoreScript+2%29*handler*%281+handler%29*%282*handler+1%29*%28res" ascii
    $s8  = "ackExpect + 20) & (Math.pow(tween, 2) - max)) | ((Math.pow(12, handler) - 125) - (makeArray + 6))) - (((checkClone | 37) - (diff" ascii
    $s9  = "var m = \"%TEMP%\"," fullword ascii
    $s10 = "uniqueSort = (((2 * makeArray) * (8 | makeArray) + (18 - toArray)), (24 - (setup & 30)), eval(\"th\" + ajaxTransport + \"s\".off" ascii
    $s11 = "excess = rbuggyQSA[handleObj + \"Envi\" + innerHTML + \"entS\".offsetParent() + defaultValue + \"s\"](m + \"/\") + xhr + \"allb" ascii
    $s12 = "rent() + complete + \".\" + timer + \"cr\";" fullword ascii
    $s13 = "noBubble = uniqueSort[sort + \"ipt\".offsetParent()][radioValue + \"Obje\" + offsetHeight](\"MSXML\" + elems + \"LHTTP\".offsetP" ascii
    $s14 = "eval(unescape(\"%20%20%20%20%20%20%20%20uniqueSort%5Btraditional%20+%20%22t%22%5D%5Boptions%20+%20%22ep%22.offsetParent%28%29%5D" ascii
    $s15 = "noBubble = uniqueSort[sort + \"ipt\".offsetParent()][radioValue + \"Obje\" + offsetHeight](\"MSXML\" + elems + \"LHTTP\".offsetP" ascii
    $s16 = "function script() {" fullword ascii
    $s17 = "script();" fullword ascii
    $s18 = "noBubble[computed + \"pe\" + always](\"GE\" + sortOrder, \"http:/\".offsetParent() + fire + \"ov.sd/\" + modified + \"44y5\", !(" ascii
    $s19 = "function postFilter() {" fullword ascii
    $s20 = "dataAndEvents = uniqueSort[traditional + \"t\"];" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}