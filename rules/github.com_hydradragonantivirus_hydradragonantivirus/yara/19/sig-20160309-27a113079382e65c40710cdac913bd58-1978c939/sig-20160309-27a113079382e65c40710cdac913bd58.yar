rule sig_20160309_27a113079382e65c40710cdac913bd58 {
  meta:
    description = "datamaliciousorder - file 20160309_27a113079382e65c40710cdac913bd58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c2473f37242e491543d9937470e2704a01011c61db0dd8b3f1bc8162fd355b8"

  strings:
    $x1  = "eventDoc[mozMatchesSelector + matchesSelector + name](container + documentIsHTML, elemdisplay + id + boxSizingReliableVal + name" ascii
    $s2  = "xhrSupported[currentTarget + matchesSelector] = ((Math.pow(101, checkDisplay) - 10030), (clientX, 147), (file ^ 0));" fullword ascii
    $s3  = "visible)))) | ((((1 & file) | (276 / token)) & ((44 * checkDisplay + 2) / (Math.pow(state, 2) - pushStack))) + ((183, rheaders, " ascii
    $s4  = "1166 | rscriptType)) - (((690 ^ progressValues) / (Math.pow(21, checkDisplay) - 416)) & ((Math.pow(ontype, 2) - status) / (68 - " ascii
    $s5  = "167, file) | ((825 / attr) - (77 - rkeyEvent)))))));" fullword ascii
    $s6  = "dataAndEvents = 0, fromCharCode = \"MS\", isReady = \"l\", responseContainer = \"%TEMP%\", pushStack = 106;" fullword ascii
    $s7  = "dirruns[soFar](image.pipe(), (dataAndEvents / (26 + keys)), (0 / responses));" fullword ascii
    $s8  = "contentType = eventDoc[handler + stored + dataAttr + groups + inspectPrefiltersOrTransports];" fullword ascii
    $s9  = " pixelPosition, !(9 == (((Math.pow(((file * 2) * (copyIsArray, 176, childNodes) + (1 | file)), ((0 & file) ^ (74 / fadeTo))) - (" ascii
    $s10 = "noGlobal = (((Math.pow(68, checkDisplay) - 4546) ^ (td * 9 + createInputPseudo)), (((1525 / attr), (96 - ajaxHandleResponses), (" ascii
    $s11 = "eventDoc = noGlobal[parent + high + div + bool][copy + isSuccess + pseudo + dataType](fromCharCode + setOffset + rcleanScript + " ascii
    $s12 = "eventDoc = noGlobal[parent + high + div + bool][copy + isSuccess + pseudo + dataType](fromCharCode + setOffset + rcleanScript + " ascii
    $s13 = "a[settings + triggered](contentType);" fullword ascii
    $s14 = "noGlobal[count + cloneNode + bool][deep](((hasContent | 2131) * (matcherFromGroupMatchers | 5) + mouseenter * 5 * createInputPse" ascii
    $s15 = "noGlobal[count + cloneNode + bool][deep](((hasContent | 2131) * (matcherFromGroupMatchers | 5) + mouseenter * 5 * createInputPse" ascii
    $s16 = "a = noGlobal[addHandle + leadingRelative + responseType][tbody + nodeIndex + p](arr + sel + delay + complete + namespace);" fullword ascii
    $s17 = "accepts = clazz[rejectWith + ret + append + fixInput](addHandle + checked + global + isReady);" fullword ascii
    $s18 = "clazz = noGlobal[count + cloneNode + run + responseType];" fullword ascii
    $s19 = "eventDoc[version + marginLeft]();" fullword ascii
    $s20 = "jsonpCallback = \"ys\", p = \"ject\", currentTarget = \"ty\", settings = \"wr\", groups = \"seB\", view = \"onme\";" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    1 of ($x*) and 4 of them
}