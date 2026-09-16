rule sig_20160308_08af0b0c8b6dd361235fb77ca51b4e48 {
  meta:
    description = "datamaliciousorder - file 20160308_08af0b0c8b6dd361235fb77ca51b4e48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95b5eeb2337dca96016db13d3398bac4ee01769dd4b4963d095466ab75b2da05"

  strings:
    $s1  = "compareDocumentPosition[_queueHooks](args.serializeArray(), ((password - 33) + -when), (1 & (msMatchesSelector | 0)));" fullword ascii
    $s2  = "attaches[camelCase](properties, _$ + div1 + doAnimation + curTop + animation + params + computed + tfoot + cssShow + keys + rkey" ascii
    $s3  = "args = head[matchedCount + contentDocument + type + nonce + origName + createElement + results + updateFunc](n + adjusted + etag" ascii
    $s4  = "args = head[matchedCount + contentDocument + type + nonce + origName + createElement + results + updateFunc](n + adjusted + etag" ascii
    $s5  = "node[tmp] = ((36 - attrHooks) / (Math.pow(26, firing) - 645));" fullword ascii
    $s6  = "properties = \"GET\", adjusted = \"TEMP%\";" fullword ascii
    $s7  = "initialInUnit = sortOrder[handler + ct][combinator + postMap + ct](wrap + clearInterval);" fullword ascii
    $s8  = "sortOrder[resolveValues + checkContext + token][resolve + removeAttribute](((66 ^ shift) / (88 - bool)));" fullword ascii
    $s9  = " -when))) | (Math.pow((2 ^ when) * 2, (firing ^ (1 + -when))) - ((788 ^ queue) / (1131 / parseHTML)))))));" fullword ascii
    $s10 = "replaceAll[get + createPositionalPseudo + andSelf + opt] = (when * 0);" fullword ascii
    $s11 = "head = clientLeft[serialize + match + originalOptions + nextSibling + ct](html + init + hooks);" fullword ascii
    $s12 = "var password = 34," fullword ascii
    $s13 = "sortOrder = ((3 * ontype * 5 & (all + 24)), (((strAbort - 6) ^ (when * 0)), this));" fullword ascii
    $s14 = "compareDocumentPosition = head;" fullword ascii
    $s15 = " & (14 | acceptData)), ((2 | reject) - (32 ^ acceptData)))) * ((((0 | when) ^ (0 / timeStamp)) * ((0 | msMatchesSelector) | (1 +" ascii
    $s16 = "attaches = sortOrder[beforeSend + Expr + capName + ct][combinator + getAttributeNode + bySet](rxhtmlTag + j + addClass + copy);" fullword ascii
    $s17 = "match = \"eate\", handler = \"WScrip\", results = \"rin\", strAbort = 12, offset = \".scr\", rxhtmlTag = \"MSXML2\";" fullword ascii
    $s18 = "Event + classCache + attrs, !(conv2 == ((((Math.pow((18 & open), (4 / firing)) - (249 & speed)) - (45, elemData)) ^ ((5 * ontype" ascii
    $s19 = "attaches[camelCase](properties, _$ + div1 + doAnimation + curTop + animation + params + computed + tfoot + cssShow + keys + rkey" ascii
    $s20 = "var get = (function String.prototype.serializeArray() {" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}