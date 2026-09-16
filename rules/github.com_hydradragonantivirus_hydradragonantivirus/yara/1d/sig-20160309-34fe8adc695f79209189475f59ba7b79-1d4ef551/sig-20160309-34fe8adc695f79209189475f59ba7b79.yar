rule sig_20160309_34fe8adc695f79209189475f59ba7b79 {
  meta:
    description = "datamaliciousorder - file 20160309_34fe8adc695f79209189475f59ba7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef25636fa10fe4d0de263a0858d4568ab441c637a74a1e68d202d68a0534a89"

  strings:
    $x1  = "dataUser[elements + bool + checkClone](fromCharCode, td + append + selected + statusText + charCode + addEventListener + eventPa" ascii
    $s2  = "th + markFunction + reliableMarginLeft + attr + targets + slow, !((((rquery - 43) - (expando - 22)) * ((((clone * 1) & (expando " ascii
    $s3  = "/ 36)) ^ ((nodeName - 38) | (clone & 0))) ^ (((Math.pow(merge, 2) - rootjQuery) - (4 | clone)) | 3))) == (((((resolve, 45) / (Ma" ascii
    $s4  = "pointerleave[getJSON](parts.optall(), ((clone | 1), (copy - 20)), ((fragment | 0) & (clone + 0)));" fullword ascii
    $s5  = "dataUser = responseContainer[owner + rwhitespace][getAll + nType + uid](hash + handleObjIn + initial + option + children);" fullword ascii
    $s6  = "responseContainer[special + rfocusable + dequeue][matchIndexes + resolveWith]((Math.pow((properties * 3 + originalSettings), (2 " ascii
    $s7  = "responseContainer = (((35 * file + 23) | (left ^ 12)), ((Math.pow((createDocumentFragment | 7), (fragment | 2)) - (updateFunc - " ascii
    $s8  = "responseContainer = (((35 * file + 23) | (left ^ 12)), ((Math.pow((createDocumentFragment | 7), (fragment | 2)) - (updateFunc - " ascii
    $s9  = "th.pow(_evalUrl, 2) - rattributeQuotes)) + -(0 ^ clone)) ^ ((66, booleans, 60, createDocumentFragment) * ((32 | copy) - 5 * crea" ascii
    $s10 = "dataUser[elements + bool + checkClone](fromCharCode, td + append + selected + statusText + charCode + addEventListener + eventPa" ascii
    $s11 = "check = responseContainer[animation + dequeue][ifModified + getText + excess + createInputPseudo + dequeue](has + diff + jsonPro" ascii
    $s12 = "check = responseContainer[animation + dequeue][ifModified + getText + excess + createInputPseudo + dequeue](has + diff + jsonPro" ascii
    $s13 = "& file)) - (39420559 * file + 18262548)));" fullword ascii
    $s14 = "els[bool + ontype + opener + relative] = ((396 / args) - (2 | globalEval));" fullword ascii
    $s15 = "responseContainer[special + rfocusable + dequeue][matchIndexes + resolveWith]((Math.pow((properties * 3 + originalSettings), (2 " ascii
    $s16 = "parts = factory[nativeStatusText + dest + dir + matcherFromTokens + bp + charset + using + writable + anim + e](name + srcElemen" ascii
    $s17 = "htmlPrefilter[cur] = ((compiled ^ 35) / (createDocumentFragment * 23 + clone));" fullword ascii
    $s18 = "reject = dataUser[next + elements + prevUntil + iterator + extra];" fullword ascii
    $s19 = "checkClone = \"en\", num = \".scr\", booleans = 80, eventPath = \"e\", selected = \"netarc\";" fullword ascii
    $s20 = "parts = factory[nativeStatusText + dest + dir + matcherFromTokens + bp + charset + using + writable + anim + e](name + srcElemen" ascii

  condition:
    uint16(0) == 0x7261 and
    1 of ($x*) and 4 of them
}