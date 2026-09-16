rule sig_20160519_c6e178ccae195c3a6257b8136b7e730e {
  meta:
    description = "datamaliciousorder - file 20160519_c6e178ccae195c3a6257b8136b7e730e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61af1cc82a175deb318ebfec0b75e7cfd5b2d7354c11597f8aa086de9d18f5c2"

  strings:
    $s1  = "var clink = [takes, overalls,marshy,  \"\"+\".\"+(\"compensate\",\"major\",\"perforated\",\"prickly\",\"sharpen\",\"labels\",\"p" ascii
    $s2  = "var stabbing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cosmetics4())&&smoker[\"c3RhdHVz\".cosmetics4()] +\"\"==\"MjAw\".co" ascii
    $s3  = "var stabbing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cosmetics4())&&smoker[\"c3RhdHVz\".cosmetics4()] +\"\"==\"MjAw\".co" ascii
    $s4  = "promise = ((\"suited\", \"grieves\", \"jetblack\", \"beneath\", \"syOCvSSEYor\") + \"jchOLa\").cosmetics2();" fullword ascii
    $s5  = "weasel = ((\"meter\", \"towing\", \"brewery\", \"welled\", \"EFshYfcBh\") + \"WupLbUpSK\").cosmetics2();" fullword ascii
    $s6  = "String.prototype.cosmetics = function () {" fullword ascii
    $s7  = "String.prototype.cosmetics4 = function() {" fullword ascii
    $s8  = "var engineer = clink.pop().split(\">\");" fullword ascii
    $s9  = "var clink = [takes, overalls,marshy,  \"\"+\".\"+(\"compensate\",\"major\",\"perforated\",\"prickly\",\"sharpen\",\"labels\",\"p" ascii
    $s10 = "String.prototype.cosmetics2 = function () {" fullword ascii
    $s11 = "var overalls =\"RXhwYW5recessionkRW52aXrecessionJvbm1lbnRTdHJrecessionpbmdz\".cosmetics4();" fullword ascii
    $s12 = "extricate(\"aHR0cDovLw==\".cosmetics4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0" ascii
    $s13 = "var relief = this[clink.shift()];" fullword ascii
    $s14 = "aspect = ((\"often\", \"tatters\", \"envelop\", \"certification\", \"pACjPzlMYttJ\") + \"GejbMzOV\").cosmetics2();" fullword ascii
    $s15 = "scimitar = this;" fullword ascii
    $s16 = "var marshy =\"JVrecessionRFTVrecessionAl\".cosmetics4();" fullword ascii
    $s17 = "var concussion = 0;" fullword ascii
    $s18 = "var shipment = new relief(engineer[1]);" fullword ascii
    $s19 = "var lawgiver = {" fullword ascii
    $s20 = "var about = 6/6;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}