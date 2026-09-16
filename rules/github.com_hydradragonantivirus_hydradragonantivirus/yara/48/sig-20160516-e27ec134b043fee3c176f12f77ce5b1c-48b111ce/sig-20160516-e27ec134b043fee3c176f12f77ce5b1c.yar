rule sig_20160516_e27ec134b043fee3c176f12f77ce5b1c {
  meta:
    description = "datamaliciousorder - file 20160516_e27ec134b043fee3c176f12f77ce5b1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0150429f575882af39affa3264e14dec184e6d122eccad2a9b382ba4244b2f4"

  strings:
    $s1  = "reward = reward+ terse.shift();" fullword ascii
    $s2  = "broken(\"aHR0cDovLw==\".mantilla4()+\"\\u0062\\u0065\\u006C\\u0075\\u0078\\u0066\\u0075\\u0072\\u006E\\u0069\\u0074\\u0075\\u007" ascii
    $s3  = "String.prototype.mantilla2 = function () {" fullword ascii
    $s4  = "String.prototype.mantilla = function () {" fullword ascii
    $s5  = "String.prototype.mantilla4 = function() {" fullword ascii
    $s6  = "        var yearn = new pervade(((\"onset\",\"bombastic\",\"subjecting\",\"sapling\",\"trend\",\"cards\",\"relaxing\",\"insured" ascii
    $s7  = "weasel = ((\"preside\", \"facial\", \"captain\", \"prostores\", \"EOBoWSx\") + \"YcbEbvT\").mantilla2();" fullword ascii
    $s8  = "var saddam = new pervade(salvador[1]);" fullword ascii
    $s9  = "  chancellor = [];" fullword ascii
    $s10 = "var collusion = 0;" fullword ascii
    $s11 = "re, false);" fullword ascii
    $s12 = "var dynamic =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".mantilla4();" fullword ascii
    $s13 = "var gospel =\"JVRFTVAl\".mantilla4();" fullword ascii
    $s14 = "var oftentimes = \"QWN0aXZlWE9iamVjdA==\".mantilla4();" fullword ascii
    $s15 = "renew = this;" fullword ascii
    $s16 = "function broken(shropshire, goblin) {" fullword ascii
    $s17 = "var pervade = this[terse.shift()];" fullword ascii
    $s18 = "var terse = [oftentimes, dynamic,gospel,  \"\"+\".\"+(\"uganda\",\"indictment\",\"bikini\",\"brave\",\"environment\",\"chancery" ascii
    $s19 = "batman = \"b3Blbg==\".mantilla4();;" fullword ascii
    $s20 = "seraph = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}