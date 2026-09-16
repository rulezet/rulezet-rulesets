rule sig_20160311_4d450fd126b18b518285fb077fc0d6c7 {
  meta:
    description = "datamaliciousorder - file 20160311_4d450fd126b18b518285fb077fc0d6c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb2ad6a30e51866cbf951b3185293f24cf03df55c53a4ad23ddbde93c85fb0b9"

  strings:
    $s1  = "height[\"op\" + module + \"n\"](pageY + \"ET\".hidden(), list + \"p://nr\" + textContent + \"ov.\" + ap + \"3r3\".hidden() + inA" ascii
    $s2  = "b = isDefaultPrevented[\"WSc\".hidden() + parentOffset][\"Creat\" + funcName + \"ject\"](getText + \".Str\".hidden() + Symbol);" fullword ascii
    $s3  = "!((((((Math.pow(4, elementMatcher) - 10)) - nextAll) + (((1 & prev) | (1 & isLocal)) + ((37 & collection) - (109 - pnum))))) > 2" ascii
    $s4  = "height[\"op\" + module + \"n\"](pageY + \"ET\".hidden(), list + \"p://nr\" + textContent + \"ov.\" + ap + \"3r3\".hidden() + inA" ascii
    $s5  = "eased = rprotocol[createFxNow + \"dEnvir\" + statusCode + \"ntSt\".hidden() + root](\"%TEM\" + now) + \"first\" + jsonProp + \"T" ascii
    $s6  = "eased = rprotocol[createFxNow + \"dEnvir\" + statusCode + \"ntSt\".hidden() + root](\"%TEM\" + now) + \"first\" + jsonProp + \"T" ascii
    $s7  = "height[colgroup + \"e\" + define]();" fullword ascii
    $s8  = "b[\"op\" + module + \"n\"]();" fullword ascii
    $s9  = "matchExpr = 19, root = \"rings\", textContent = \"o.g\", oldCallbacks = \"ect\";" fullword ascii
    $s10 = "easing = isDefaultPrevented[types + \"ript\"];" fullword ascii
    $s11 = "n() + module + \".\" + colgroup + \"cr\";" fullword ascii
    $s12 = "rprotocol = easing[parent + \"eObjec\" + vendorPropName](\"WScri\".hidden() + notifyWith + \"ll\");" fullword ascii
    $s13 = "b[unquoted + \"File\".hidden()](eased, ((tfoot / 33) + (isLocal + 0)));" fullword ascii
    $s14 = "extra[vendorPropName + \"yp\".hidden() + module] = (isLocal + 0);" fullword ascii
    $s15 = "function matcherFromTokens() {" fullword ascii
    $s16 = "return submit" fullword ascii
    $s17 = "function clientLeft() {" fullword ascii
    $s18 = "active();" fullword ascii
    $s19 = "var collection = 55," fullword ascii
    $s20 = "parent = \"Creat\"," fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}