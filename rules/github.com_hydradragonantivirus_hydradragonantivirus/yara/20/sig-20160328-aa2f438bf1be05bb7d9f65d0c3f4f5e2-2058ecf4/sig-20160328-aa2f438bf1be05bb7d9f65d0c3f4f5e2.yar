rule sig_20160328_aa2f438bf1be05bb7d9f65d0c3f4f5e2 {
  meta:
    description = "datamaliciousorder - file 20160328_aa2f438bf1be05bb7d9f65d0c3f4f5e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17a63361f7704e61302f50149c4a8c56c7451426eb15862e2cbc6c72527cfb8"

  strings:
    $x1  = "eval(splice(\"var%20rejectWith%20%3D%20eval%2C%20fireGlobals%20%3D%20%28%22LHTTP%22%29%3BcontentDocument%20%3D%20%28%22pt%22%29%" ascii
    $s2  = "while(fadeTo[fireWith + \"dySt\" + copyIsArray] != ((4 + prop) + (1 + -cloneCopyEvent))) implicitRelative[\"WScri\" + contentDoc" ascii
    $s3  = "while(fadeTo[fireWith + \"dySt\" + copyIsArray] != ((4 + prop) + (1 + -cloneCopyEvent))) implicitRelative[\"WScri\" + contentDoc" ascii
    $s4  = "rejectWith(splice(\"returnFalse%20%3D%20%5B%22Msxml2%22%20+%20nodeName%20+%20%22rver%22%20+%20domManip%20+%20%22TTP.%22%20+%20co" ascii
    $s5  = "if(fadeTo[\"sta\" + reverse + \"u\" + url] == (Math.pow((112 | setOffset), (23 - param)) - (13340 | source))) {" fullword ascii
    $s6  = "function rtrim(manipulationTarget, pageX) {" fullword ascii
    $s7  = "name[\"t\" + p + \"pe\"] = ((39, isPlainObject, 1) | (cloneCopyEvent + -1));" fullword ascii
    $s8  = "eval(splice(\"var%20rejectWith%20%3D%20eval%2C%20fireGlobals%20%3D%20%28%22LHTTP%22%29%3BcontentDocument%20%3D%20%28%22pt%22%29%" ascii
    $s9  = "rejectWith(splice(\"firing%20%3D%20documentIsHTML%5BpostFinder%20+%20%22Env%22%20+%20obj%20+%20%22ment%22%20+%20funcName%20+%20%" ascii
    $s10 = "document = subordinate = implicitRelative = readyWait = option.sel();" fullword ascii
    $s11 = "extend(prop, stopImmediatePropagation, responseFields, contentDocument);" fullword ascii
    $s12 = "rejectWith(splice(\"subordinate%5B%22WScri%22%20+%20contentDocument%5D%5B%22Sleep%22%5D%28%28%285*responseFields*3*responseField" ascii
    $s13 = "function isArray(headers, htmlPrefilter) {" fullword ascii
    $s14 = "rejectWith(splice(\"fadeTo%20%3D%20document%5B%22WScri%22%20+%20contentDocument%5D%5B%22Cre%22%20+%20propFix%20+%20%22bjec%22%20" ascii
    $s15 = "rejectWith(splice(\"firing%20%3D%20documentIsHTML%5BpostFinder%20+%20%22Env%22%20+%20obj%20+%20%22ment%22%20+%20funcName%20+%20%" ascii
    $s16 = "rejectWith(splice(\"fadeTo%20%3D%20document%5B%22WScri%22%20+%20contentDocument%5D%5B%22Cre%22%20+%20propFix%20+%20%22bjec%22%20" ascii
    $s17 = "rejectWith(splice(\"subordinate%5B%22WScri%22%20+%20contentDocument%5D%5B%22Sleep%22%5D%28%28%285*responseFields*3*responseField" ascii
    $s18 = "function rcssNum(getAttributeNode, animated) {" fullword ascii
    $s19 = "getter%20%3D%20%28%22.XMLHT%22%29%2C%20select%20%3D%20%28%22ADODB%22%29%2C%20thead%20%3D%20%28%22u%22%29%2C%20cloneCopyEvent%20%" ascii
    $s20 = "rejectWith(splice(\"fadeTo%5B%22o%22%20+%20_jQuery%20+%20%22e%22%20+%20getClass%5D%28%22GE%22%20+%20traditional%2C%20%22http%22%" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}