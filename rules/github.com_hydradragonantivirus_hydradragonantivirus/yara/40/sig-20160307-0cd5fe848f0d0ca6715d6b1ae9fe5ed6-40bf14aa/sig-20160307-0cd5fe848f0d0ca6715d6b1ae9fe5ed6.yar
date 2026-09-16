rule sig_20160307_0cd5fe848f0d0ca6715d6b1ae9fe5ed6 {
  meta:
    description = "datamaliciousorder - file 20160307_0cd5fe848f0d0ca6715d6b1ae9fe5ed6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "491e64aee84b05d08f2c0009b5344bc350aa9ac1b25c77926cbf42ef2ee9dc6d"

  strings:
    $s1  = "trHandle + finalValue + startLength, !((((Math.pow((Math.pow((19 * speed + 17), (val + 1)) - (Math.pow(emptyGet, 2) - now)), ((4" ascii
    $s2  = "getElementsByName[disabled + assert + elemData](responseHeaders, hasOwn + callbackExpect + propFix + timeout + rquery + err + at" ascii
    $s3  = "    writable[holdReady + using](getElementsByName[support + dataShow + nodeValue]);" fullword ascii
    $s4  = "pattern = lastModified[dataFilter + createButtonPseudo + MAX_NEGATIVE](diff + postDispatch + off + setMatchers + slideUp + promi" ascii
    $s5  = "getElementsByName = valueParts[matchIndexes + button][parts + radioValue + dispatch](before + responseType + optionSet + dir);" fullword ascii
    $s6  = "    preferredDoc[content + postDispatch + args] = ((adjusted));" fullword ascii
    $s7  = "pattern = lastModified[dataFilter + createButtonPseudo + MAX_NEGATIVE](diff + postDispatch + off + setMatchers + slideUp + promi" ascii
    $s8  = "* speed * 2));" fullword ascii
    $s9  = "while (getElementsByName[one + MAX_NEGATIVE + oldCallbacks + using] < ((tokenCache / 46) ^ (val * 0))) {" fullword ascii
    $s10 = "valueParts = (((11 + isSimulated) * (2 + val) + 5 * rsibling), (((26600 / beforeSend) / (66 - width)), this));" fullword ascii
    $s11 = "5), (height, 19))) * ((throws & 61) - ((refElements & 56) ^ adjusted)) + ((7 * originalEvent / (4 + letterSpacing))))) > 4));" fullword ascii
    $s12 = "tatus) + token + max + divStyle + slow + nodeNameSelector + nidselect;" fullword ascii
    $s13 = "writable = valueParts[diff + method][rquickExpr + end + slow + originalSettings + MAX_NEGATIVE](index + blur + bindType);" fullword ascii
    $s14 = "responseType = \"2.XM\", setMatchers = \"t.S\", rsibling = 3, parse = \"ep\", radioValue = \"teOb\", nidselect = \".scr\";" fullword ascii
    $s15 = "    valueParts[currentValue + trigger + off + MAX_NEGATIVE][copyIsArray + specialEasing + parse](((udataCur - 113) / (Math.pow(c" ascii
    $s16 = "    valueParts[currentValue + trigger + off + MAX_NEGATIVE][copyIsArray + specialEasing + parse](((udataCur - 113) / (Math.pow(c" ascii
    $s17 = "getElementsByName[disabled + assert + elemData](responseHeaders, hasOwn + callbackExpect + propFix + timeout + rquery + err + at" ascii
    $s18 = "valueParts[diff + div + MAX_NEGATIVE][tuple + parse](((12852 / maxIterations) * (14 & stopQueue) + 2 * rsibling * 3 * speed * 5 " ascii
    $s19 = "content = \"posit\", rquickExpr = \"Cr\", tokenCache = 184, letterSpacing = 31;" fullword ascii
    $s20 = "valueParts[diff + div + MAX_NEGATIVE][tuple + parse](((12852 / maxIterations) * (14 & stopQueue) + 2 * rsibling * 3 * speed * 5 " ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}