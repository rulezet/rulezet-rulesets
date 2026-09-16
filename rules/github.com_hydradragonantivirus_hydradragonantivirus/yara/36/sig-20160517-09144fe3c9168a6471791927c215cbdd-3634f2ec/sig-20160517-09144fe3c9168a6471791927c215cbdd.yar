rule sig_20160517_09144fe3c9168a6471791927c215cbdd {
  meta:
    description = "datamaliciousorder - file 20160517_09144fe3c9168a6471791927c215cbdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c2e77195a20f08c37f9aa174fdbc8ae6659654c0a58d865ef5561d049fc285"

  strings:
    $s1  = "var facing=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".handheld4())&&apostolic[\"c3RhdHVz\".handheld4()] +\"\"==\"MjAw\".han" ascii
    $s2  = "var facing=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".handheld4())&&apostolic[\"c3RhdHVz\".handheld4()] +\"\"==\"MjAw\".han" ascii
    $s3  = "secondary[collectively.shift()](greatly, injection, true);" fullword ascii
    $s4  = "portentous = ((\"nerve\", \"outrun\", \"hairy\", \"telecharger\", \"sxvQjGgAJa\") + \"zehDDTDK\").handheld2();" fullword ascii
    $s5  = "var injection = 6/6;" fullword ascii
    $s6  = "weasel = ((\"semicircle\", \"talmud\", \"ancestry\", \"paradise\", \"EBFJooVKV\") + \"pqiEXDyNeY\").handheld2();" fullword ascii
    $s7  = "    apostolic[portentous + (\"hygienic\",\"exponent\",\"end\")]();" fullword ascii
    $s8  = "toLowerCase())](anterior, injection);" fullword ascii
    $s9  = "nters\",\"computation\",\"unconstitutional\",\"anomaly\",\"experimenting\",\"08\"), portentous)] = 0;" fullword ascii
    $s10 = "        mined.type = injection;" fullword ascii
    $s11 = "var apostolic = new ventral(coffer[0]);" fullword ascii
    $s12 = "        mined[(woody + \"o\"+(\"manipulation\",\"orthodoxy\",\"universities\",\"labels\",\"origins\",\"keyword\",\"mixture\",\"s" ascii
    $s13 = "var biotechnology = secondary[collectively.shift()](collectively.shift());" fullword ascii
    $s14 = "greatly = greatly+ collectively.shift();" fullword ascii
    $s15 = "woody = ((\"sensor\", \"manganese\", \"inexpensive\", \"characteristics\", \"pxklVUUYIhtp\") + \"wPeuSlLpCS\").handheld2();" fullword ascii
    $s16 = "        var greatly = biotechnology + \"/\" + fertilizing ;" fullword ascii
    $s17 = "diagram(\"aHR0cDovLw==\".handheld4()+\"\\u0069\\u006E\\u006E\\u0061\\u0074\\u0065\\u0073\\u0079\\u006E\\u0065\\u0072\\u0067\\u00" ascii
    $s18 = "String.prototype.handheld4 = function() {" fullword ascii
    $s19 = "var coffer = collectively.pop().split(\"" fullword ascii
    $s20 = "String.prototype.handheld = function () {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}