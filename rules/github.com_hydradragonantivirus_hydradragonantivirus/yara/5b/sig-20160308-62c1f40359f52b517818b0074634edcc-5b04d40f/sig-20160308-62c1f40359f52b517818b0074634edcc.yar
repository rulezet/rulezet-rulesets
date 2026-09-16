rule sig_20160308_62c1f40359f52b517818b0074634edcc {
  meta:
    description = "datamaliciousorder - file 20160308_62c1f40359f52b517818b0074634edcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48f2ac02421bd8920a1593697a22fd60169c2e87696190f2ec99d31f04f1eab9"

  strings:
    $s1  = "selection[linear](shift, image + isWindow + getClass + show + acceptData + selector + delegate + contains + delegate + iframe + " ascii
    $s2  = "_jQuery[createPseudo + merge + byElement + end](styles, ((2 ^ which) + (17 - forward)));" fullword ascii
    $s3  = "selection = speed[select + matched + isWindow][assert + host + end + origFn + adjustCSS + proxy](module + createTextNode + setOf" ascii
    $s4  = "selection = speed[select + matched + isWindow][assert + host + end + origFn + adjustCSS + proxy](module + createTextNode + setOf" ascii
    $s5  = "_jQuery = speed[select + window + stop][b + origType + createComment + lastChild](getText + checkNonElements + matchContext);" fullword ascii
    $s6  = " speed[diff + stop][throws + parentOffset]((Math.pow((node), (1 ^ superMatcher)) - (1100 | updateFunc)));" fullword ascii
    $s7  = "ofType = \"%TEMP%\", checkNonElements = \"ODB.S\", pixelMarginRight = \"cript\", define = \"cl\";" fullword ascii
    $s8  = "box[preventDefault + eventPath] = ((10 | aup), (25 + rrun), (376 - random), (1 + -inspect));" fullword ascii
    $s9  = "ialize)), ((1 * inspect) * (2 ^ which))) - (Math.pow(68, dir) - 4551) * (inspect + 1) * (inspect * 2)), ((Math.pow((etag | 8), (" ascii
    $s10 = "speed = (((84 - tweeners)), (((1 * charCode) / (Math.pow(5, dir) - 18)), this));" fullword ascii
    $s11 = "rjsonp = createButtonPseudo[removeAttribute + setTimeout + mapped + dispatch + lastChild](removeProp + pixelMarginRight + msMatc" ascii
    $s12 = "createButtonPseudo = speed[removeProp + rscriptType + window + stop];" fullword ascii
    $s13 = " + inspect)) & ((5 + forward), (31 & dataAndEvents), (494 * dir + 33)))))));" fullword ascii
    $s14 = "_jQuery[original](selection[getResponseHeader + apply + pixelPosition + rmargin + pixelMarginRightVal]);" fullword ascii
    $s15 = "preferredDoc[trigger](styles.pixelPositionVal(), ((0 ^ which) ^ (1 & which)), ((26 - parseJSON) & (16 - one)));" fullword ascii
    $s16 = " dir) - 1527849) / (valueParts / 19)), ((parseFromString, 219, serialize, 1) * (inspect * 0))) | ((elementMatcher * 2 + (seriali" ascii
    $s17 = "selection[linear](shift, image + isWindow + getClass + show + acceptData + selector + delegate + contains + delegate + iframe + " ascii
    $s18 = "styles = rjsonp[matchIndexes + optSelected + last + dirruns + l + text + contentDocument](ofType + after) + hasDuplicate + toSel" ascii
    $s19 = "styles = rjsonp[matchIndexes + optSelected + last + dirruns + l + text + contentDocument](ofType + after) + hasDuplicate + toSel" ascii
    $s20 = "speed[base + isWindow][val + createInputPseudo + curPosition](((4680000 / rrun) / (13 + parseJSON)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}