rule sig_20160308_17fb9a6441e1f0041f01bc29e9e11f0d {
  meta:
    description = "datamaliciousorder - file 20160308_17fb9a6441e1f0041f01bc29e9e11f0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b87ceb6e2b9b52aafafa31f74952c3672bafc4673c81846b79e057efdcf3acd"

  strings:
    $s1  = "rmultiDash[id](dataPriv, constructor + originalEvent + fnOver + rrun + addBack + push + code + doAnimation + overflowX + sortOrd" ascii
    $s2  = "while (rmultiDash[css + finalDataType + isArray + JSON + finalDataType] < ((9 * createComment + 3) - (Math.pow(getById, 2) - rel" ascii
    $s3  = "while (rmultiDash[css + finalDataType + isArray + JSON + finalDataType] < ((9 * createComment + 3) - (Math.pow(getById, 2) - rel" ascii
    $s4  = "setRequestHeader = nextAll[rnotwhite + JSON + finalDataType + updateFunc + hold + handleObjIn](targets + addEventListener + nTyp" ascii
    $s5  = "remove[handleObj + clearTimeout][expand + add]((Math.pow((getAll | 1580), (createInputPseudo | 2)) - (args)));" fullword ascii
    $s6  = "setRequestHeader = nextAll[rnotwhite + JSON + finalDataType + updateFunc + hold + handleObjIn](targets + addEventListener + nTyp" ascii
    $s7  = "tokens[flag + check + finalDataType](rmultiDash[textContent + rcheckableType + ajaxTransport]);" fullword ascii
    $s8  = "rmultiDash = remove[handleObj + fadeToggle + responseFields][rnotwhite + isNumeric + getAllResponseHeaders + r20](contentType + " ascii
    $s9  = "  remove[targets + handleObjIn][stopImmediatePropagation + unwrap](((4 ^ manipulationTarget) * 2 + (dir * 16)));" fullword ascii
    $s10 = "rmultiDash = remove[handleObj + fadeToggle + responseFields][rnotwhite + isNumeric + getAllResponseHeaders + r20](contentType + " ascii
    $s11 = "(rmouseEvent, 79, width, 9)))) + (((xhrFields | (1 * createInputPseudo)) * ((0 / cacheLength) ^ (23 - password))) - 2 * (dir ^ (" ascii
    $s12 = "tokens[createTextNode + complete + fired](append, 2);" fullword ascii
    $s13 = "open = \"Create\", getComputedStyle = \"g\", fadeIn = \"op\";" fullword ascii
    $s14 = "ajaxPrefilter[handleObjIn + defer] = ((0 | xhrFields) ^ (20 - display));" fullword ascii
    $s15 = "password = 20;" fullword ascii
    $s16 = "remove = (((1 + xhrFields) * (11 & once)), (((42 - tweener) ^ (0 / conv2)), this));" fullword ascii
    $s17 = "tokens[fadeIn + click]();" fullword ascii
    $s18 = "rmultiDash[id](dataPriv, constructor + originalEvent + fnOver + rrun + addBack + push + code + doAnimation + overflowX + sortOrd" ascii
    $s19 = "tokens = remove[fire + step + handleObjIn][open + beforeSend](merge + replaceChild + handleObjIn + radioValue + returnFalse);" fullword ascii
    $s20 = "nextAll = remove[globalEventContext + stopImmediatePropagation + ready + handleObjIn];" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}