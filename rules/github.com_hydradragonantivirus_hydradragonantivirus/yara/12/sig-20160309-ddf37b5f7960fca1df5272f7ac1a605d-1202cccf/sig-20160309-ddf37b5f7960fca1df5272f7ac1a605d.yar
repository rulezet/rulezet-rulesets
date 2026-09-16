rule sig_20160309_ddf37b5f7960fca1df5272f7ac1a605d {
  meta:
    description = "datamaliciousorder - file 20160309_ddf37b5f7960fca1df5272f7ac1a605d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e0e5c17424867a50deca5ee62907e0428a261e4d9f13186c0e80d91f89717a2"

  strings:
    $x1  = "stopPropagation[position](bindType + source, exports + pageYOffset + identifier + string + events + forward + parentOffset + inP" ascii
    $s2  = "(stateVal - 44), (nodes ^ 13))), (((udataCur - 136) - (cors / 49))), (((target & 90)) / ((iNoClone + 22) & (cssShow / 8)))) + ((" ascii
    $s3  = "age + srcElements + dataShow + triggerHandler, !(4 < (((((prototype ^ 109), (relatedTarget / 18), (disconnectedMatch - 204)) / (" ascii
    $s4  = "stopPropagation[position](bindType + source, exports + pageYOffset + identifier + string + events + forward + parentOffset + inP" ascii
    $s5  = "keyCode = onlyHandlers[p + hold + name][offset + rxhtmlTag + bind + lastChild](attrNames + tmp + padding + tmp + textContent + m" ascii
    $s6  = "keyCode = onlyHandlers[p + hold + name][offset + rxhtmlTag + bind + lastChild](attrNames + tmp + padding + tmp + textContent + m" ascii
    $s7  = "keyCode[returnFalse + send + filters + docElem + rsubmitterTypes](prefix, ((166, toSelector) - (Math.pow(23, iframe) - 493)));" fullword ascii
    $s8  = "pixelMarginRightVal + -((49 & handlers) - 2 * iframe * 2 * iframe * 3)) ^ (((each - 77) / (sort - 5)) / ((module / 44) ^ (readyS" ascii
    $s9  = "target = 107," fullword ascii
    $s10 = "stopPropagation = onlyHandlers[_default + blur][complete + dataAndEvents + throws + padding + expanded + async](risSimple + addT" ascii
    $s11 = "radio = onlyHandlers[p + getBoundingClientRect + blur];" fullword ascii
    $s12 = "onlyHandlers = (((242, swing) & (146 | rreturn)), (((101 - originalProperties) - (28 + statusText)), this));" fullword ascii
    $s13 = "onlyHandlers[msMatchesSelector + name][clearInterval + high](((reject - 6804) + (reliableMarginLeft * 2 + stateString)));" fullword ascii
    $s14 = "curTop = radio[offset + opt + div](_default + onreadystatechange + register + namespace + excess);" fullword ascii
    $s15 = "stopPropagation = onlyHandlers[_default + blur][complete + dataAndEvents + throws + padding + expanded + async](risSimple + addT" ascii
    $s16 = "oPrefiltersOrTransports + orig + value);" fullword ascii
    $s17 = "forward = \"yst\";" fullword ascii
    $s18 = "parts = elems + speed;" fullword ascii
    $s19 = "createInputPseudo = stopPropagation[setMatchers + firing + ret + etag];" fullword ascii
    $s20 = "identifier = \"hsani\";" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}