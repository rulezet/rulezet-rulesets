rule sig_20160325_118db7556ccd924f1a6e3f0c4716c74f {
  meta:
    description = "datamaliciousorder - file 20160325_118db7556ccd924f1a6e3f0c4716c74f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db93bd848b762772a169fad16516bb8cfda972f6bbbf55c80b8c590120a078f9"

  strings:
    $s1  = "getWidthOrHeight[\"WScrip\" + clearCloneStyle][\"Slee\" + charset]((Math.pow((1093 * sortDetached + 541), (apply - 18)) - (inner" ascii
    $s2  = "getWidthOrHeight[\"WScrip\" + clearCloneStyle][\"Slee\" + charset]((Math.pow((1093 * sortDetached + 541), (apply - 18)) - (inner" ascii
    $s3  = "var isArray = [][\"const\" + complete + \"r\"][clearInterval + \"oty\" + nonce][\"s\" + keys + \"t\"][requestHeaders + \"p\" + p" ascii
    $s4  = "clearTimeout = reverse = dataUser = getWidthOrHeight = run.find();" fullword ascii
    $s5  = "prototype = dataUser[\"WScri\" + hasCompare];" fullword ascii
    $s6  = "eval(test(\"pdataCur%20%3D%20new%20getWidthOrHeight%5Bstyle%20+%20%22eXObj%22%20+%20delegateTarget%5D%28%22Msx%22%20+%20fired%20" ascii
    $s7  = "eval(test(\"pdataCur%20%3D%20new%20getWidthOrHeight%5Bstyle%20+%20%22eXObj%22%20+%20delegateTarget%5D%28%22Msx%22%20+%20fired%20" ascii
    $s8  = "postSelector(apply, setMatcher, andSelf, delegateTarget);" fullword ascii
    $s9  = "eval(test(\"pdataCur%5Bval%20+%20%22en%22%5D%28firingIndex%20+%20%22E%22%20+%20rfocusable%2C%20%22http%3A/%22%20+%20addHandle%20" ascii
    $s10 = "function password() {" fullword ascii
    $s11 = "password(andSelf, pageY);" fullword ascii
    $s12 = "eval(test(\"rhtml%28th%20+%20%22onseB%22%20+%20restoreScript%2C%20%28%28checkNonElements%26435%29/%28margin-30%29%29%2C%20clearQ" ascii
    $s13 = "restoreScript = (function run() {}, \"ody\")," fullword ascii
    $s14 = "eval(test(\"rhtml%28th%20+%20%22onseB%22%20+%20restoreScript%2C%20%28%28checkNonElements%26435%29/%28margin-30%29%29%2C%20clearQ" ascii
    $s15 = "function postSelector() {" fullword ascii
    $s16 = "originalEvent[superMatcher](pdataCur[operator]);" fullword ascii
    $s17 = "function rhtml(operator, onabort, originalEvent, superMatcher) {" fullword ascii
    $s18 = "pdataCur[\"s\" + open + \"d\"]();" fullword ascii
    $s19 = "createPositionalPseudo = trim[setMatcher + \"andEn\" + merge + \"nmentS\" + nextSibling + \"ngs\"](buildFragment + \"P%/\") + ha" ascii
    $s20 = "createPositionalPseudo = trim[setMatcher + \"andEn\" + merge + \"nmentS\" + nextSibling + \"ngs\"](buildFragment + \"P%/\") + ha" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}