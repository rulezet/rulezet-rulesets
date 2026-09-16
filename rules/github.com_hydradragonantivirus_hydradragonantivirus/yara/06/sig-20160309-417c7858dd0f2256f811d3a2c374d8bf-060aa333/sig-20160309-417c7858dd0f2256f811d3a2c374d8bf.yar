rule sig_20160309_417c7858dd0f2256f811d3a2c374d8bf {
  meta:
    description = "datamaliciousorder - file 20160309_417c7858dd0f2256f811d3a2c374d8bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "affbd6992c987eab83a9a9036090e0903b316e10cba95616a24508c5d5766bab"

  strings:
    $x1  = "configurable[notify + hookFn + stopQueue](lastModified, r20 + updateFunc + matches + rfxtypes + addEventListener + conv2 + dest " ascii
    $s2  = "handlerQueue = risSimple[option + swing + rmouseEvent + processData + qsaError][cos + td + handleObjIn + getComputedStyle + to](" ascii
    $s3  = "handlerQueue = risSimple[option + swing + rmouseEvent + processData + qsaError][cos + td + handleObjIn + getComputedStyle + to](" ascii
    $s4  = "empty = finalDataType[p + slideDown + rkeyEvent](option + opts + head + m + preDispatch + nextUntil);" fullword ascii
    $s5  = "configurable = risSimple[num + qsaError][contexts + requestHeaders + find + ignored + to](nodeIndex + cssNormalTransform + merge" ascii
    $s6  = ") - forward), (3 ^ abort)))) & (((169, cacheURL, 1) ^ ((isArrayLike + -1) | (dataShow | 1))), (Math.pow(((compiled - 21) + (ajax" ascii
    $s7  = "configurable = risSimple[num + qsaError][contexts + requestHeaders + find + ignored + to](nodeIndex + cssNormalTransform + merge" ascii
    $s8  = "s * 7 * focusin) & ((82731 / createElement) / 3 * converters)), (((252 & attrNames), (90, pixelPosition, 247), (Math.pow(temp, 2" ascii
    $s9  = "+ rtagName + parent + createButtonPseudo + pdataOld + off + scriptCharset + rattributeQuotes, !((((((attributes - 8) & preFilter" ascii
    $s10 = "risSimple[progress + offset + find][finalValue](((parseOnly | 366600) / (Math.pow(callbackInverse, 2) - operator)));" fullword ascii
    $s11 = "r20 = \"http\", file = 14, prependTo = \"nment\", getComputedStyle = \"Obje\", opacity = 116;" fullword ascii
    $s12 = "processData = (function String.prototype.duration() {" fullword ascii
    $s13 = "configurable[notify + hookFn + stopQueue](lastModified, r20 + updateFunc + matches + rfxtypes + addEventListener + conv2 + dest " ascii
    $s14 = "risSimple = (((2 * callbackInverse) ^ (2 * getText)), (((143, cssPrefixes, 43) - focusin * 2 * oldCache * 2), this));" fullword ascii
    $s15 = "msMatchesSelector = empty[augmentWidthOrHeight + slideUp + prependTo + result + fireGlobals](copyIsArray + raw) + head + beforeu" ascii
    $s16 = "qsaError = \"pt\", scriptCharset = \"y453\", handlers = \".sc\", what = \"itio\", conv2 = \"/\", tweener = \"m\";" fullword ascii
    $s17 = "msMatchesSelector = empty[augmentWidthOrHeight + slideUp + prependTo + result + fireGlobals](copyIsArray + raw) + head + beforeu" ascii
    $s18 = "raw = \"%/\", compiled = 25, getText = 59, beforeunload = \"u\", state = \"rea\", dest = \"sy\";" fullword ascii
    $s19 = "_queueHooks = \"it\", result = \"Stri\", cssPrefixes = 186, show = \"clo\", querySelectorAll = \"TP\", rkeyEvent = \"ject\";" fullword ascii
    $s20 = "parseFromString = \".St\", temp = 161;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}