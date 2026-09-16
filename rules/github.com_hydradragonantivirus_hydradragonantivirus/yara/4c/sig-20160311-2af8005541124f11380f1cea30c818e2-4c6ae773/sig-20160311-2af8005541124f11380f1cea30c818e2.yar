rule sig_20160311_2af8005541124f11380f1cea30c818e2 {
  meta:
    description = "datamaliciousorder - file 20160311_2af8005541124f11380f1cea30c818e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f228f22240177369a6c542bf165948235af224335269544feafcc960531032"

  strings:
    $x1  = "readyList = temp[eventDoc + \"t\".fire()][operator + \"teObje\" + progressContexts](\"MSX\" + inspected + \".XMLHT\".fire() + pr" ascii
    $x2  = "readyList = temp[eventDoc + \"t\".fire()][operator + \"teObje\" + progressContexts](\"MSX\" + inspected + \".XMLHT\".fire() + pr" ascii
    $s3  = "readyList[\"op\" + deepDataAndEvents](\"GE\" + ajaxHandleResponses, \"http:\".fire() + protocol + \".28.2\" + statusCode + \"9/h" ascii
    $s4  = "cssFn = temp[eventDoc + \"t\".fire()][rwhitespace + \"eObj\" + transport](\"ADOD\" + rfxtypes + \"am\".fire());" fullword ascii
    $s5  = "readyList[\"op\" + deepDataAndEvents](\"GE\" + ajaxHandleResponses, \"http:\".fire() + protocol + \".28.2\" + statusCode + \"9/h" ascii
    $s6  = "eventHandle = temp[\"WScri\" + uniqueSort];" fullword ascii
    $s7  = "temp = (((371 | dir) - (288 / fcamelCase)), (1 * (setAttribute & 11)), eval(\"t\" + stopImmediatePropagation + \"i\".fire() + cl" ascii
    $s8  = "temp = (((371 | dir) - (288 / fcamelCase)), (1 * (setAttribute & 11)), eval(\"t\" + stopImmediatePropagation + \"i\".fire() + cl" ascii
    $s9  = "scale[\"R\" + cos](apply.fire(((window - 423) / (fireWith | 23))), ((getAll * 1) + -(v / 50)), ((getAll * 0) | (to - 5)));" fullword ascii
    $s10 = "apply = structure[\"Expan\" + firstElementChild + \"onm\".fire() + isXMLDoc + \"trings\"](xhrFields + \"MP%/\") + elemData + \"u" ascii
    $s11 = ") + tokens + \".\" + animation + \"r\";" fullword ascii
    $s12 = "operator = \"Crea\";" fullword ascii
    $s13 = "structure = eventHandle[\"Cre\" + whitespace + \"bject\".fire()](propHooks + \"pt.S\" + dataTypeExpression);" fullword ascii
    $s14 = "cssFn[\"saveT\" + hold](apply, (2 & propFix));" fullword ascii
    $s15 = "cssFn[param + \"e\" + test]();" fullword ascii
    $s16 = "apply = structure[\"Expan\" + firstElementChild + \"onm\".fire() + isXMLDoc + \"trings\"](xhrFields + \"MP%/\") + elemData + \"u" ascii
    $s17 = "transport = \"ect\"," fullword ascii
    $s18 = "test = \"n\";" fullword ascii
    $s19 = "function createHTMLDocument() {" fullword ascii
    $s20 = "hold = \"oFile\", statusCode = \"11.19\", inspected = \"ML2\", _data = \"w\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}