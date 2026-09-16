rule sig_20160329_095db688fa14ea05b24979eae027910a {
  meta:
    description = "datamaliciousorder - file 20160329_095db688fa14ea05b24979eae027910a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36c718d4c03fc60c896531ad6897a3aed7a71029eac591632893f9dedb61a3f3"

  strings:
    $s1  = "if (fail[\"st\" + postFinder] == ((686 - arg) - (7800 / compareDocumentPosition))) {" fullword ascii
    $s2  = "fail = host[\"WScri\" + uniqueSort][\"Create\" + get](cssNormalTransform[finish]);" fullword ascii
    $s3  = "has[version + \"pt\"][elements + \"le\" + dataUser](((197344 / document) & (Math.pow(5747, preexisting) - 33021980)));" fullword ascii
    $s4  = "isEmptyObject(\"while%20%28fail%5Brclickable%20+%20%22dySta%22%20+%20slideToggle%5D%20%21%3D%20%28%28chainable%2C160%2Cpreexisti" ascii
    $s5  = "isEmptyObject(\"fail%5B%22o%22%20+%20node%20+%20%22e%22%20+%20mouseHooks%5D%28%22G%22%20+%20docElem%20+%20%22T%22%2C%20push_nati" ascii
    $s6  = "getElementById[\"Wr\" + vendorPropName](fail[\"resp\" + tweener + \"ody\"]);" fullword ascii
    $s7  = "function merge(processData) {" fullword ascii
    $s8  = "getElementById[\"o\" + node + \"e\" + mouseHooks]();" fullword ascii
    $s9  = "isEmptyObject(\"delay%5Bversion%20+%20%22pt%22%5D%5Belements%20+%20%22le%22%20+%20dataUser%5D%28%28%28addEventListener*10+fadeTo" ascii
    $s10 = "getElementById[\"m\" + innerHTML + \"e\"] = ((1 & curOffset) * (95, count));" fullword ascii
    $s11 = "for (finish = ((curOffset + 0) + -(preexisting - 1)); finish < cssNormalTransform[div1]; finish++) {" fullword ascii
    $s12 = "augmentWidthOrHeight(compareDocumentPosition, getElementsByTagName, easing);" fullword ascii
    $s13 = "fail[prevObject + \"e\" + mouseHooks + \"d\"]();" fullword ascii
    $s14 = "has = host = parentNode = delay = originalSettings._removeData();" fullword ascii
    $s15 = "isEmptyObject(\"delay%5Bversion%20+%20%22pt%22%5D%5Belements%20+%20%22le%22%20+%20dataUser%5D%28%28%28addEventListener*10+fadeTo" ascii
    $s16 = "getElementById[factory + \"pe\"] = ((34 / camel) * 1);" fullword ascii
    $s17 = "function throws(getResponseHeader) {" fullword ascii
    $s18 = "hasOwn(speeds, uniqueSort, until, getElementsByTagName, mouseHooks);" fullword ascii
    $s19 = "throws(prevObject, dataUser, getElementsByTagName, cacheURL, random);" fullword ascii
    $s20 = "function identifier() {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}