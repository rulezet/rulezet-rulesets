rule sig_20160311_834611a22f1a988bc65d7c9a6b59e487 {
  meta:
    description = "datamaliciousorder - file 20160311_834611a22f1a988bc65d7c9a6b59e487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "087522f78c72a404757a5d543f17ecad31558845a3d366636efdc59db48fe1ba"

  strings:
    $s1  = "unloadHandler[\"o\" + swing + \"n\"](slow + \"E\".nodeIndex() + initial, \"http\" + eventDoc + \"50.2\" + unshift + \"11.1\".nod" ascii
    $s2  = "e, 168, restoreScript), (765 / overflow)))), ((((26 - xhr) + 5 * reliableMarginLeft) + ((476 - values) & (Math.pow(242, preDispa" ascii
    $s3  = "overflowY = (((2368 / selected) - (12 * preDispatch + 3)), (Math.pow((nodes, 116, push), (1 + toggle)) - (97 - getAttribute)), e" ascii
    $s4  = "overflowY = (((2368 / selected) - (12 * preDispatch + 3)), (Math.pow((nodes, 116, push), (1 + toggle)) - (97 - getAttribute)), e" ascii
    $s5  = "binary[\"R\".nodeIndex() + method + \"n\"](prevAll.nodeIndex(((Math.pow(84, preDispatch) - 6931) & (Math.pow(s, 2) - createOptio" ascii
    $s6  = "binary[\"R\".nodeIndex() + method + \"n\"](prevAll.nodeIndex(((Math.pow(84, preDispatch) - 6931) & (Math.pow(s, 2) - createOptio" ascii
    $s7  = "etAttributeNode + \"0/8\" + addHandle + \"76u5y4\", !(((((2 + view) | (50 / writable)) * (Math.pow((12 + restoreScript), (2 | vi" ascii
    $s8  = " - (36 | gotoEnd)) * ((57 & tweeners) - (Math.pow(7, preDispatch) - 39)) / (((code * 2 + _$) / (73 - elements)) / ((27 & checkbo" ascii
    $s9  = "tch) - 58235))) / ((Math.pow((uid * 5 + cos), 2) - (off & 392154)) / ((cssNormalTransform / 36) - (toggle * 11))))) > push));" fullword ascii
    $s10 = "w[propHooks + \"eToF\" + reverse](prevAll, ((43 / originalOptions) * (7 - mozMatchesSelector)));" fullword ascii
    $s11 = "), ((17 + noBubble), 61 * preDispatch * 2, (view, 0)), ((toggle & 1) + -toggle));" fullword ascii
    $s12 = "fixHook[\"ty\".nodeIndex() + swing] = ((1 & toggle) + (1 + -toggle));" fullword ascii
    $s13 = "x) - (75, mappedTypes, 151, genFx)))), ((((19600 + setter) & (23422 & hold)) / ((36 & showHide) | 3 * overflow)) - (((360 - incl" ascii
    $s14 = "unloadHandler = overflowY[\"WScrip\".nodeIndex() + opts][\"Create\" + elemLang + \"ct\"](sortDetached + \".XML\".nodeIndex() + s" ascii
    $s15 = "unloadHandler[\"o\" + swing + \"n\"](slow + \"E\".nodeIndex() + initial, \"http\" + eventDoc + \"50.2\" + unshift + \"11.1\".nod" ascii
    $s16 = "getAttributeNode = \"99/hdd\", originalSettings = \"MP%\", rheader = 34, xhr = 17, elements = 46, swing = \"pe\";" fullword ascii
    $s17 = "val(\"t\" + factory + \"is\".nodeIndex()));" fullword ascii
    $s18 = "gerH\".nodeIndex() + base + \"ler\" + second + \"s\" + children;" fullword ascii
    $s19 = "unloadHandler[all + \"en\".nodeIndex() + container]();" fullword ascii
    $s20 = "udeWidth) & (7018 / reliableMarginLeft)) & (2 * preDispatch * 2 * preDispatch * 7 * preDispatch, (1534 / ofType), (65, returnTru" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}