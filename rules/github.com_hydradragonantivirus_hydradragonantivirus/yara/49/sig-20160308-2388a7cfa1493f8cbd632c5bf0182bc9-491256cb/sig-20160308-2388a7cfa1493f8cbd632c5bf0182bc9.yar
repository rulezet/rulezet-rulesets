rule sig_20160308_2388a7cfa1493f8cbd632c5bf0182bc9 {
  meta:
    description = "datamaliciousorder - file 20160308_2388a7cfa1493f8cbd632c5bf0182bc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7144244753ea09f15b29041c635f8e30f278398e8bcee9cad113df2c662a60c5"

  strings:
    $s1  = "body[e](xhr + getter, dequeue + optionSet + off + token + noop + div1 + notify + rcssNum, !(rclass == ((Math.pow(((1 + -(getAttr" ascii
    $s2  = "gotoEnd[then](compile.isWindow(), (1 + -(proxy, 1)), ((getAttribute) + -(0 ^ getAttribute)));" fullword ascii
    $s3  = "ibute ^ 0)) | ((sourceIndex & 639) / (getAttribute | 25))), rclass) - (((4 * rclass) | (3560 / operator)), ((Math.pow(41, rclass" ascii
    $s4  = "step = cssNormalTransform[propFix + temp + responseHeadersString][createButtonPseudo + htmlPrefilter + fadeTo + subtract](dataSh" ascii
    $s5  = "step = cssNormalTransform[propFix + temp + responseHeadersString][createButtonPseudo + htmlPrefilter + fadeTo + subtract](dataSh" ascii
    $s6  = "body[e](xhr + getter, dequeue + optionSet + off + token + noop + div1 + notify + rcssNum, !(rclass == ((Math.pow(((1 + -(getAttr" ascii
    $s7  = "body = cssNormalTransform[lname + responseHeadersString][delay + fadeTo + subtract](elements + rfxtypes + uniqueSort + keepScrip" ascii
    $s8  = "responseHeadersString = \"ipt\", noop = \".com\", load = 15, checked = \"l\";" fullword ascii
    $s9  = "cssNormalTransform = (((Math.pow(74, rclass) - 5395) | (postSelector / 38)), (((keys, 59, diff, 8) | (soFar + 1)), this));" fullword ascii
    $s10 = ") - 1610) + (load ^ 28)), ((onlyHandlers - 100) - (fix, 109, elemdisplay, 34)))) - (((getAttribute ^ 0) + (div, 86, getAttribute" ascii
    $s11 = "step[parseOnly + getResponseHeader + has](compile, ((getAttribute + -1) ^ rclass));" fullword ascii
    $s12 = "step[insertAfter + checked + second + head]();" fullword ascii
    $s13 = "body = cssNormalTransform[lname + responseHeadersString][delay + fadeTo + subtract](elements + rfxtypes + uniqueSort + keepScrip" ascii
    $s14 = "nodeValue = resolveWith[contexts + nativeStatusText + contentType](copyIsArray + set + deepDataAndEvents + createElement + first" ascii
    $s15 = "parseOnly = \"save\", addToPrefiltersOrTransports = \"WScrip\", operator = 40;" fullword ascii
    $s16 = "step[tabIndex + msMatchesSelector](body[expanded + end + bp + num + focusin]);" fullword ascii
    $s17 = "compile = nodeValue[inPage + eq + curTop + fadeIn + matched + defaultPrefilter](_queueHooks + to) + insertAfter + triggerHandler" ascii
    $s18 = "init = \"send\", inspect = \".scr\";" fullword ascii
    $s19 = "compile = nodeValue[inPage + eq + curTop + fadeIn + matched + defaultPrefilter](_queueHooks + to) + insertAfter + triggerHandler" ascii
    $s20 = "closest = \"ODB.St\", temp = \"cr\", div1 = \"/8\", has = \"e\";" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}