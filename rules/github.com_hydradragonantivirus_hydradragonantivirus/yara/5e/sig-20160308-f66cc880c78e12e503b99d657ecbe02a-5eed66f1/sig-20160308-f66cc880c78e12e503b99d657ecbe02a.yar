rule sig_20160308_f66cc880c78e12e503b99d657ecbe02a {
  meta:
    description = "datamaliciousorder - file 20160308_f66cc880c78e12e503b99d657ecbe02a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a58f2333e520ee438b8db085595aec3e8a3cc98d7dcf3bebe096e96f3a0ed722"

  strings:
    $s1  = "second = \"%TEMP%\", emptyGet = \"port\", backgroundClip = \"Run\", writable = \"entS\";" fullword ascii
    $s2  = "completeDeferred[currentTarget + getter] = ((1 * head) ^ 0);" fullword ascii
    $s3  = "inPage = (((66 | sortDetached) * (2 | head) + (29 ^ unbind)), (((69 - setAttribute) | (1 + -aup)), this));" fullword ascii
    $s4  = "isPlainObject = ajax[win + root + prevUntil + writable + newDefer + th + sortInput + replaceChild](second + bindType) + deep + r" ascii
    $s5  = "while(propName[removeEvent + readyWait] < (3 & vendorPropName) * (2 ^ head)) {" fullword ascii
    $s6  = "propName[removeData](opt, nodeType + curCSS + specified + rsubmitterTypes + callbackExpect + newCache + dataAttr + contents + in" ascii
    $s7  = "isPlainObject = ajax[win + root + prevUntil + writable + newDefer + th + sortInput + replaceChild](second + bindType) + deep + r" ascii
    $s8  = "th = \"r\", clientX = \"seBody\", opt = \"GET\", contents = \"i8\", newDefer = \"t\", curLeft = \"l\";" fullword ascii
    $s9  = "dataTypeExpression[conv2 + DOMParser] = (1 ^ head);" fullword ascii
    $s10 = "sertBefore + refElements, !(9 < (((rbrace - 39) | (isLocal / 25)), ((replaceWith | 41) & (hidden & 111)), ((rsingleTag / 10) | (" ascii
    $s11 = "getter = \"tion\";" fullword ascii
    $s12 = "global[noGlobal](isPlainObject.hasClass(), ((aup * 0) & (noop / 24)), (head ^ 0));" fullword ascii
    $s13 = "head = 0," fullword ascii
    $s14 = "owner = \"ite\", getAll = \"Crea\", box = \"Scr\";" fullword ascii
    $s15 = "propName[removeData](opt, nodeType + curCSS + specified + rsubmitterTypes + callbackExpect + newCache + dataAttr + contents + in" ascii
    $s16 = "expand = inPage[reset + newDefer];" fullword ascii
    $s17 = "rparentsprev[width + owner](propName[children + clientX]);" fullword ascii
    $s18 = "inPage[fcamelCase + box + overwritten][isDefaultPrevented + undelegate](((15289 & remaining) & (48282 / fail)));" fullword ascii
    $s19 = "root = \"dEnvir\"," fullword ascii
    $s20 = "ajax = expand[parsed + events + hasData](classes + dirruns + isWindow + specified + removeProp + innerText + curLeft);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}