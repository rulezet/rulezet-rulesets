rule sig_20160308_778ecc640857fdda8e022eb65590492c {
  meta:
    description = "datamaliciousorder - file 20160308_778ecc640857fdda8e022eb65590492c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cdce058f48aaa21790ce8006c32c539f9c9eef5e62796d26f982f8383fd4879"

  strings:
    $s1  = "flag = \"n\", rtagName = 29, global = \"r\", fixInput = \"erso\", target = 11, processData = \"s\";" fullword ascii
    $s2  = "concat[newSelector + global + clientX][origName]((Math.pow(box, 2) - readyList) * (78, delegateTarget) * 3 * (delegateTarget ^ 0" ascii
    $s3  = "concat[newSelector + global + clientX][origName]((Math.pow(box, 2) - readyList) * (78, delegateTarget) * 3 * (delegateTarget ^ 0" ascii
    $s4  = "settings[processData + compareDocumentPosition + locked + disconnectedMatch + escaped](display, ((66 - cloneNode), (100 / origin" ascii
    $s5  = "settings[processData + compareDocumentPosition + locked + disconnectedMatch + escaped](display, ((66 - cloneNode), (100 / origin" ascii
    $s6  = "concat = ((23 * target - (20 ^ origFn)), ((Math.pow((13 | curElem), 2) - opt * 5), this));" fullword ascii
    $s7  = "nd, 2) - tick))) - ((155, dataTypeExpression, 3) * (removeProp + 5) * (rcomma | 28) * (rcomma + 1) / ((pointerleave, 57, pointer" ascii
    $s8  = "text[specified + to + flag] = ((1 * rcomma) + -(1 + createButtonPseudo));" fullword ascii
    $s9  = "5 + tag)), ((8 * box + 6) - (Math.pow(firstChild, 2) - suffix))) - (160524 / (Math.pow(activeElement, 2) - rtagName))), ((1 * (r" ascii
    $s10 = "rreturn = \"od\", createButtonPseudo = 0, delegateTarget = 5, cloneNode = 35, stop = \"seB\";" fullword ascii
    $s11 = "concat[contextBackup + preferredDoc][ct + opacity](((accepts ^ 72), (round & 254), (ajaxPrefilter & 232), removeProp * 5 * deleg" ascii
    $s12 = "sortDetached[cacheLength](preFilter + isTrigger, first + showHide + invert + attachEvent + cssPrefixes + multipleContexts + fixI" ascii
    $s13 = "nput + reset + rclass + callbackInverse + _removeData, !((((Math.pow((Math.pow((curElem + 87), (rcomma ^ 3)) - (oldCallbacks * 2" ascii
    $s14 = "comma + 0)) * (removeProp * (2 + createButtonPseudo) + (0 | rcomma)))) + ((((34 / result) * 1) | ((rcomma ^ 0) | (Math.pow(prepe" ascii
    $s15 = "temp = \"gs\"," fullword ascii
    $s16 = "eq[preferredDoc + checked] = (1 & rcomma);" fullword ascii
    $s17 = "display = colgroup[unquoted + clearQueue + isWindow + locked + attr + global + href + flag + temp](_$ + capName + marginRight) +" ascii
    $s18 = "display = colgroup[unquoted + clearQueue + isWindow + locked + attr + global + href + flag + temp](_$ + capName + marginRight) +" ascii
    $s19 = "colgroup = originalSettings[replaceAll + base + transports + dataFilter](contextBackup + firstDataType + step);" fullword ascii
    $s20 = "settings = concat[ret + getJSON + prevAll][maxWidth + body + tbody](jsonProp + isHidden + global + locked + setMatched);" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    8 of them
}