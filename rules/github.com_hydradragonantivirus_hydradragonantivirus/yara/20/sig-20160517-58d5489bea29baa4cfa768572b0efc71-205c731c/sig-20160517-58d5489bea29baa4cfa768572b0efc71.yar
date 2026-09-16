rule sig_20160517_58d5489bea29baa4cfa768572b0efc71 {
  meta:
    description = "datamaliciousorder - file 20160517_58d5489bea29baa4cfa768572b0efc71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "191aabfa5f0a59523aebfd93b72f109b8fdcb66e3bea128a6fcd3dd99303ee09"

  strings:
    $s1  = "        brazil[(accident + \"o\"+(\"folding\",\"liberate\",\"liberate\",\"paolo\",\"crocodile\",\"premise\",\"phone\",\"horizon" ascii
    $s2  = "var yugoslavia=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".burlington4())&&unaccompanied[\"c3RhdHVz\".burlington4()] +\"\"==" ascii
    $s3  = "var yugoslavia=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".burlington4())&&unaccompanied[\"c3RhdHVz\".burlington4()] +\"\"==" ascii
    $s4  = "        var brazil = new disciplinary(((\"thompson\",\"plaid\",\"equivalent\",\"newcomer\",\"almost\",\"acceptation\",\"incompar" ascii
    $s5  = "accident = ((\"seaport\", \"century\", \"ostensible\", \"disband\", \"pXHgPtD\") + \"LuVvUW\").burlington2();" fullword ascii
    $s6  = "var awesome = [shank, incumbent,tiptoe,  \"\"+\".\"+(\"scandals\",\"canning\",\"sonata\",\"spinach\",\"obeisance\",\"ratios\",\"" ascii
    $s7  = "var unaccompanied = new disciplinary(shared[0]);" fullword ascii
    $s8  = "weasel = ((\"specials\", \"reduction\", \"arthritis\", \"twoedged\", \"EFApTfr\") + \"tXnVVF\").burlington2();" fullword ascii
    $s9  = "String.prototype.burlington2 = function () {" fullword ascii
    $s10 = "function configurations(corners, walker) {" fullword ascii
    $s11 = "String.prototype.burlington = function () {" fullword ascii
    $s12 = "String.prototype.burlington4 = function() {" fullword ascii
    $s13 = "    unaccompanied[burthen + (\"debater\",\"outdo\",\"end\")]();" fullword ascii
    $s14 = "var awesome = [shank, incumbent,tiptoe,  \"\"+\".\"+(\"scandals\",\"canning\",\"sonata\",\"spinach\",\"obeisance\",\"ratios\",\"" ascii
    $s15 = "            unaccompanied[contain]((\"blackjack\",\"encamp\",\"G\" + weasel) + (\"brazilian\",\"summary\",\"ports\",\"jewelry\"," ascii
    $s16 = "            unaccompanied[contain]((\"blackjack\",\"encamp\",\"G\" + weasel) + (\"brazilian\",\"summary\",\"ports\",\"jewelry\"," ascii
    $s17 = "var disciplinary = this[awesome.shift()];" fullword ascii
    $s18 = "for (var i in christine){designer = designer.replace(i, christine[i]);}" fullword ascii
    $s19 = "var tiptoe =\"JVRFTVAl\".burlington4();" fullword ascii
    $s20 = "designer = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}