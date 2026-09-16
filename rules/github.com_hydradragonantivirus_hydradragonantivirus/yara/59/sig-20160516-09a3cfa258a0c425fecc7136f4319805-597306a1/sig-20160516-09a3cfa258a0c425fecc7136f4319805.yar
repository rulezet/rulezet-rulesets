rule sig_20160516_09a3cfa258a0c425fecc7136f4319805 {
  meta:
    description = "datamaliciousorder - file 20160516_09a3cfa258a0c425fecc7136f4319805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56d59f2d2ec87f4e8f7d7836f5a393687f44e1d2f72d373fbc921f58a88275a9"

  strings:
    $s1  = "var difference = [exhort, combination,effectiveness,  \"\"+\".\"+(\"vsnet\",\"liberate\",\"scratch\",\"conduce\",\"taciturn\",\"" ascii
    $s2  = "weasel = ((\"modelling\", \"futility\", \"stifle\", \"secretive\", \"EtRCFrq\") + \"ftyjQzmbg\").moira2();" fullword ascii
    $s3  = "\"meters\",\"called\",\"buffer\",\"seasick\",\"ip\")+\"t:\"+(\"fresher\",\"casinos\",\"stripling\",\"depend\",\"maria\",\"stack" ascii
    $s4  = "var tributary=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".moira4())&&episode[\"c3RhdHVz\".moira4()] +\"\"==\"MjAw\".moira4()" ascii
    $s5  = "var tributary=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".moira4())&&episode[\"c3RhdHVz\".moira4()] +\"\"==\"MjAw\".moira4()" ascii
    $s6  = "var episode = new overhead(susan[0]);" fullword ascii
    $s7  = "var overhead = this[difference.shift()];" fullword ascii
    $s8  = "var erudition = new overhead(susan[1]);" fullword ascii
    $s9  = "        var distance = new overhead(((\"coldblooded\",\"nothingness\",\"gross\",\"kenny\",\"stuart\",\"thompson\",\"albert\",\"b" ascii
    $s10 = "ding\",\"outdoors\",\"apathetic\",\"appendix\",\"marvin\",\"lemonade\",\"exclude\",\"8i\")+\"tion\").replace(\"0\"+(\"behind\"," ascii
    $s11 = "quota(\"aHR0cDovLw==\".moira4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065\\u002F\\u00" ascii
    $s12 = "var difference = [exhort, combination,effectiveness,  \"\"+\".\"+(\"vsnet\",\"liberate\",\"scratch\",\"conduce\",\"taciturn\",\"" ascii
    $s13 = "String.prototype.moira2 = function () {" fullword ascii
    $s14 = "String.prototype.moira4 = function() {" fullword ascii
    $s15 = "var combination =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".moira4();" fullword ascii
    $s16 = "String.prototype.moira = function () {" fullword ascii
    $s17 = "        var distance = new overhead(((\"coldblooded\",\"nothingness\",\"gross\",\"kenny\",\"stuart\",\"thompson\",\"albert\",\"b" ascii
    $s18 = "function quota(ventures, bastard) {" fullword ascii
    $s19 = "var effectiveness =\"JVRFTVAl\".moira4();" fullword ascii
    $s20 = "        distance[(\"hostelry\",\"providence\",\"premises\",\"uprising\",\"titanium\",\"steam\",\"ennui\",\"w\")+\"ri\"+\"te\"](e" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}