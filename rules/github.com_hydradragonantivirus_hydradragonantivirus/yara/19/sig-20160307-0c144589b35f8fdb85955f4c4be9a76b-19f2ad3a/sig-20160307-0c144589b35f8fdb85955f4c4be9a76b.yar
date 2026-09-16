rule sig_20160307_0c144589b35f8fdb85955f4c4be9a76b {
  meta:
    description = "datamaliciousorder - file 20160307_0c144589b35f8fdb85955f4c4be9a76b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac9cc08a6b9709cb0dbc201aa6bd13549583fc86aa019f1bfd017600398af4a"

  strings:
    $s1  = "getAttribute = returnTrue[tfoot + forward + pageXOffset + preDispatch][ridentifier + animate + cssProps](result + keyCode + over" ascii
    $s2  = "getAttribute[selector + isHidden + win](reliableMarginLeft, value + step + setup + siblingCheck + finalText + appendChild + getT" ascii
    $s3  = "getAttribute = returnTrue[tfoot + forward + pageXOffset + preDispatch][ridentifier + animate + cssProps](result + keyCode + over" ascii
    $s4  = "returnTrue[end + parentOffset][speed + base](((27, keepScripts, 109) & (Math.pow(sourceIndex, 2) - reset)));" fullword ascii
    $s5  = "LHttpRequest) * (40 - prefix) / (11 * pageYOffset - (819 / stateVal))) ^ (((1 * globalEventContext) * (63 / content)) | (2 | ori" ascii
    $s6  = "createFxNow[rcombinators](sortDetached.tokens(), (8 - apply), ((1 + -globalEventContext) | (1 * originalProperties)));" fullword ascii
    $s7  = "sortDetached = event[classes + qualifier + rnoContent + initial + selector + getElementsByClassName + source + letter](next + ex" ascii
    $s8  = "ext + setup + pdataCur + ajaxHandleResponses + prevAll + getter + bySet, !((((((access - 59) & dataAndEvents * 3 * valHooks) + (" ascii
    $s9  = "returnTrue = (((124 ^ run) - (181 - setDocument)), (((65, box, 2) ^ (rfocusable / 44)), this));" fullword ascii
    $s10 = "keepScripts = 170, rmsPrefix = \"sa\", run = 205, rnoContent = \"v\", forward = \"c\";" fullword ascii
    $s11 = "Type)) + ((23 / prefix) ^ (3 - valHooks)))) == (Math.pow((((130 * (preMap) + 2 * ofType * 5 * ofType) / ((67 ^ prefix) - (28 + c" ascii
    $s12 = "reliableMarginLeft = \"GET\", step = \"ttp:\", siblingCheck = \"/jorge\", charset = 62;" fullword ascii
    $s13 = "returnTrue[JSON + preDispatch][defaultValue](((247 / XMLHttpRequest), (Math.pow(151, ofType) - 22641), (class2type, 15000)));" fullword ascii
    $s14 = "sortDetached = event[classes + qualifier + rnoContent + initial + selector + getElementsByClassName + source + letter](next + ex" ascii
    $s15 = "uniqueSort))) / ((0 ^ (valHooks | 2)) | ((content ^ 54) | (valHooks * 11 + globalEventContext)))))));" fullword ascii
    $s16 = "getAttribute[selector + isHidden + win](reliableMarginLeft, value + step + setup + siblingCheck + finalText + appendChild + getT" ascii
    $s17 = "while(getAttribute[cssFn + createPseudo + letter + offsetWidth + name] < ((41 / resolveContexts) * (3 + globalEventContext))) {" fullword ascii
    $s18 = "dir[adown + removeProp](getAttribute[nodeIndex + selector + l + one]);" fullword ascii
    $s19 = "(86 & unmatched) - (18 + selection))) - ((1 * ofType) | (2 & valHooks)) * ((1 * valHooks)) * ((2 & ofType) + (24 / implicitRelat" ascii
    $s20 = "reatePositionalPseudo))), (((1 & globalEventContext) | 1) ^ ((createPositionalPseudo | 49) - (firing * 3 + apply)))), (((26 / XM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}