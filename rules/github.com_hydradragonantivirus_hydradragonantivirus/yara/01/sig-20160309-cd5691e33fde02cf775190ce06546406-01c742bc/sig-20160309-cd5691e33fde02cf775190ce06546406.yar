rule sig_20160309_cd5691e33fde02cf775190ce06546406 {
  meta:
    description = "datamaliciousorder - file 20160309_cd5691e33fde02cf775190ce06546406.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08a6371054783df3ec486e300012b359f0948fd14e38a09dc8307361250b1d43"

  strings:
    $s1  = "_load[unit](optgroup, contentDocument + letterSpacing + createDocumentFragment + pixelPosition + replaceAll + rscriptType + spli" ascii
    $s2  = "_load[unit](optgroup, contentDocument + letterSpacing + createDocumentFragment + pixelPosition + replaceAll + rscriptType + spli" ascii
    $s3  = "currentValue = rbrace[preFilters + xml + namespaces + which + divStyle + password + mimeType + isXML + matchedCount](animate + d" ascii
    $s4  = "isNumeric[merge + setTimeout][getBoundingClientRect + createComment](((28, global, 231, reset) ^ 3 * constructor * 2 * opts * 3 " ascii
    $s5  = "currentValue = rbrace[preFilters + xml + namespaces + which + divStyle + password + mimeType + isXML + matchedCount](animate + d" ascii
    $s6  = "ce + radioValue + params + parseJSON + a + tabIndex + reliableMarginLeft, !(8 < ((((rchecked - 24) & (empty | 1))) ^ ((((nativeS" ascii
    $s7  = "isNumeric = (((34 + type), (0 | parseOnly), (13 * testContext + 7), (valueIsBorderBox * 3 + rrun)), ((41 - origType), this));" fullword ascii
    $s8  = "elems[unmatched + pageX](currentValue, ((14 / getter) * (0 | tuples)));" fullword ascii
    $s9  = "getBoundingClientRect = \"Sl\", splice = \"s.pk/\", rrun = 30, rmargin = (function Object.prototype.stopQueue() {" fullword ascii
    $s10 = "load = \"sCo\", contentDocument = \"http:/\", nativeStatusText = 12;" fullword ascii
    $s11 = "rnoInnerhtml[destElements](currentValue.stopQueue(), (2 * constructor - (161, input)), ((1 | empty) + -(26 - rchecked)));" fullword ascii
    $s12 = "preFilters = \"Exp\", merge = \"WScri\", responseHeadersString = 15, global = 82, replaceAll = \"ined\", ridentifier = \"ha\";" fullword ascii
    $s13 = "password = \"nt\";" fullword ascii
    $s14 = "isNumeric[merge + setTimeout][getBoundingClientRect + createComment](((28, global, 231, reset) ^ 3 * constructor * 2 * opts * 3 " ascii
    $s15 = "var setup = \".scr\"," fullword ascii
    $s16 = "elems = isNumeric[orig + remaining + always + len][clientY + len + pixelPositionVal + rcombinators + len](copyIsArray + rmsPrefi" ascii
    $s17 = "efaultPrevented) + ridentifier + load + Sizzle + $ + setup;" fullword ascii
    $s18 = "elems = isNumeric[orig + remaining + always + len][clientY + len + pixelPositionVal + rcombinators + len](copyIsArray + rmsPrefi" ascii
    $s19 = "slideToggle = \"cr\", $ = \"re\", getter = 14;" fullword ascii
    $s20 = "hasFocus = isNumeric[merge + setTimeout];" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}