rule sig_20160328_a197c00159765d122970145452d54999 {
  meta:
    description = "datamaliciousorder - file 20160328_a197c00159765d122970145452d54999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd9f1c4dc7bddb0ac11844f7ee6e9e5a72ab35c927e00317785aac9edd0f64dd"

  strings:
    $s1  = "animated(noGlobal(\"requestHeaders%20%3D%20%5Bcompleted%20+%20%22ml2.Se%22%20+%20box%20+%20%22rXML%22%20+%20cssText%20+%20%22P.6" ascii
    $s2  = "eased[isNumeric + \"Fil\" + resolveContexts](temp, ((matcher * 2) & (script & 3)));" fullword ascii
    $s3  = "for (guid = ((matcher + -1) | inPage); guid < requestHeaders[\"len\" + fadeTo]; guid++) {" fullword ascii
    $s4  = "_removeData[\"Ru\" + evt](temp);" fullword ascii
    $s5  = "write = style[\"WScri\" + acceptData][\"Crea\" + nodes + \"ct\"](requestHeaders[guid]);" fullword ascii
    $s6  = "animated(noGlobal(\"requestHeaders%20%3D%20%5Bcompleted%20+%20%22ml2.Se%22%20+%20box%20+%20%22rXML%22%20+%20cssText%20+%20%22P.6" ascii
    $s7  = "solve%20+%20%222.X%22%20+%20elemLang%20+%20%22TP%22%2C%20ajaxTransport%20+%20%22soft.%22%20+%20getWindow%20+%20%22P%22%5D%3B\"))" ascii
    $s8  = "write[\"s\" + resolveContexts + \"n\" + xhrSupported]();" fullword ascii
    $s9  = "while (write[\"read\" + rmouseEvent] != ((attr + 0) * (attr | 2))) closest[\"WScr\" + tr][\"Sleep\"](((iNoClone + 1239) / (clone" ascii
    $s10 = "send(createInputPseudo, animated, hasContent);" fullword ascii
    $s11 = "animated(noGlobal(\"write%5BclearTimeout%20+%20%22p%22%20+%20pointerenter%5D%28%22G%22%20+%20offsetWidth%2C%20%22http%3A/%22%20+" ascii
    $s12 = "filter(getWindow, andSelf, genFx, _evalUrl);" fullword ascii
    $s13 = "eased[toggle + \"e\" + evt]();" fullword ascii
    $s14 = "if (write[winnow + \"us\"] == ((96 * attr) | (7 + matcher))) {" fullword ascii
    $s15 = "animated(noGlobal(\"_removeData%20%3D%20style%5B%22WScr%22%20+%20tr%5D%5B%22Create%22%20+%20seekingTransport%20+%20%22t%22%5D%28" ascii
    $s16 = "bindType(resolve, elem, refElements, animated, binary);" fullword ascii
    $s17 = "animated(noGlobal(\"eased%20%3D%20style%5BpropFix%20+%20%22ipt%22%5D%5Bletter%20+%20%22ateO%22%20+%20grep%20+%20%22t%22%5D%28sto" ascii
    $s18 = "animated(noGlobal(\"temp%20%3D%20_removeData%5BcallbackName%20+%20%22Envir%22%20+%20prevObject%20+%20%22tStrin%22%20+%20prop%5D%" ascii
    $s19 = "animated(noGlobal(\"write%5BclearTimeout%20+%20%22p%22%20+%20pointerenter%5D%28%22G%22%20+%20offsetWidth%2C%20%22http%3A/%22%20+" ascii
    $s20 = "animated(noGlobal(\"eased%5B%22mo%22%20+%20xhrSupported%20+%20%22e%22%5D%20%3D%20%28%281%26matcher%29*%282+matcher%29%29%3B\"));" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}