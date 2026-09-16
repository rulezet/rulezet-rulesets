rule sig_20160307_9e544faa2a2c903288b60e07e91903c6 {
  meta:
    description = "datamaliciousorder - file 20160307_9e544faa2a2c903288b60e07e91903c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9876370d2f4ffb51cebb719ac1fe8ef69d6eaec732c0523fa3cb24810aad2f0b"

  strings:
    $x1  = "realStringObj[target + r20](old + jsonProp, rnative + run + callbackContext + values + returnTrue + arr + lname + node + readySt" ascii
    $s2  = "* 2 * fire / (Math.pow(32, rhash) - 984)) ^ ((tr - 984) / (contentType / 6)))) | ((((pseudos & 1) * sibling) | (2 | sibling)) + " ascii
    $s3  = "ate + noGlobal, !((((((14 + selector) - (125 - defaultExtra)) + ((Math.pow(31, rhash) - 929))) - ((guaranteedUnique * 2 * rhash " ascii
    $s4  = "firstDataType[target + r20]();" fullword ascii
    $s5  = "realStringObj[target + r20](old + jsonProp, rnative + run + callbackContext + values + returnTrue + arr + lname + node + readySt" ascii
    $s6  = "slideDown[extend + propName][replaceAll + argument + charset]((Math.pow((2063 * guaranteedUnique + 1993), (className - 26)) - (r" ascii
    $s7  = "detach[globalEventContext + then] = ((amd * 2 + rhash) / (73 - filters));" fullword ascii
    $s8  = "props = \"l\", target = \"op\";" fullword ascii
    $s9  = "slideDown[compiled + expand][pushStack + charset](((16 | ignored) & (43, dataTypeOrTransport)));" fullword ascii
    $s10 = "rcleanScript = 140066295, old = \"G\", original = \"WS\", noGlobal = \"r\", compiled = \"WSc\";" fullword ascii
    $s11 = "image = eventHandle[isBorderBox + getJSON + msMatchesSelector + globalEventContext](extend + letter + documentIsHTML + clientTop" ascii
    $s12 = " + getResponseHeader + props);" fullword ascii
    $s13 = "image = eventHandle[isBorderBox + getJSON + msMatchesSelector + globalEventContext](extend + letter + documentIsHTML + clientTop" ascii
    $s14 = "firstDataType[rprotocol + dest + option + select + invert + timeoutTimer](unquoted, ((progressContexts ^ 20) / (createOptions - " ascii
    $s15 = "firstDataType[rprotocol + dest + option + select + invert + timeoutTimer](unquoted, ((progressContexts ^ 20) / (createOptions - " ascii
    $s16 = "scrollTo[modified](unquoted.ajaxHandleResponses(), ((sibling ^ 4) - (tbody - 21)), (sibling / 10));" fullword ascii
    $s17 = "while (realStringObj[opacity + nType + success] < (cached - 6) * rhash) {" fullword ascii
    $s18 = "slideDown = (((58 - guaranteedUnique) ^ (80 * rhash + 34)), ((oldCache - (315 / delegate)), this));" fullword ascii
    $s19 = "slideDown[extend + propName][replaceAll + argument + charset]((Math.pow((2063 * guaranteedUnique + 1993), (className - 26)) - (r" ascii
    $s20 = "delegate = 15, sortStable = \"y\", propName = \"Script\", run = \"/\", adjustCSS = \"WScrip\", JSON = \"seBod\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}