rule sig_20160311_684bba4a231c542f7328a22466000eb9 {
  meta:
    description = "datamaliciousorder - file 20160311_684bba4a231c542f7328a22466000eb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac6d3ce47306c66850df00083aba43ddfbaf0294c154f4a640226cde4f96b43a"

  strings:
    $s1  = "updateFunc[statusCode + \"pe\" + resolveWith](\"G\".position() + camelCase, \"http:\" + preFilter + \"umy\" + swing + \"ce.r\".p" ascii
    $s2  = " contains) | (160 / m)) + ((Math.pow(21, rsubmitterTypes) - 415) - (fired - 2))) & ((Math.pow((head | 1), rsubmitterTypes) - (53" ascii
    $s3  = "rnoContent[\"saveT\" + isPropagationStopped](run, ((1 * setup) | (51 - opener)));" fullword ascii
    $s4  = "a - 54)), ((setup | 2) & (contains * 2))) - (on + (6 & Symbol))), (150, tokens, 179, rsubmitterTypes)) - (((376 - insertAfter) /" ascii
    $s5  = "updateFunc[statusCode + \"pe\" + resolveWith](\"G\".position() + camelCase, \"http:\" + preFilter + \"umy\" + swing + \"ce.r\".p" ascii
    $s6  = " 2 * rsubmitterTypes * 3 * rsubmitterTypes * 2) * ((contains * 3) + contains) + ((1 + setup) * (32 / p)))) - ((((0 & setup) | (1" ascii
    $s7  = " - fn)) + ((31725 / extend) / (47 + setup))))) == ((Math.pow((Math.pow(((239, size, 81), (fn | 18), (removeClass | 152), (hasDat" ascii
    $s8  = "updateFunc = dataUser[\"WScr\".position() + boxSizingReliable][\"Cre\" + rhash + \"bject\"](owner + \"ML2.X\".position() + hooks" ascii
    $s9  = "updateFunc = dataUser[\"WScr\".position() + boxSizingReliable][\"Cre\" + rhash + \"bject\"](owner + \"ML2.X\".position() + hooks" ascii
    $s10 = "href = dataUser[\"WScrip\" + display];" fullword ascii
    $s11 = "run = username[\"Expand\" + node + \"onm\".position() + scrollLeft + \"Stri\" + grep](\"%TEM\" + iNoClone) + \"cont\".position()" ascii
    $s12 = "run = username[\"Expand\" + node + \"onm\".position() + scrollLeft + \"Stri\" + grep](\"%TEM\" + iNoClone) + \"cont\".position()" ascii
    $s13 = "rattributeQuotes[unmatched + \"p\" + realStringObj] = contains;" fullword ascii
    $s14 = "r, 11))) * ((on & 5) * (contains * 2) * rsubmitterTypes * (1 * rsubmitterTypes) + ((8 + sort) & (140 / ajaxConvert)))) / ((((0 &" ascii
    $s15 = "71, contains)) & (1 + setup)) | ((1 & (contains)) * (0 | (size / 28)))))));" fullword ascii
    $s16 = "username = href[\"Create\" + Callbacks](\"WScr\".position() + returned + \"She\" + optDisabled);" fullword ascii
    $s17 = "unbind();" fullword ascii
    $s18 = "cacheURL[\"R\" + _evalUrl](run.position(((ajaxSettings * 4 + implementation) & (30 * rsubmitterTypes + 29))), (setup), (0 / rsub" ascii
    $s19 = "function unbind() {" fullword ascii
    $s20 = "setup = 0, seekingTransport = \"ateObj\", padding = \"tion\", ajaxConvert = 14;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}