rule sig_20160516_31c227e00820aacce049c8d676224502 {
  meta:
    description = "datamaliciousorder - file 20160516_31c227e00820aacce049c8d676224502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2249e10b27381e4ade0e0ec857ea0d6d40da7c0c67656644b308ff442a0488"

  strings:
    $s1  = "weasel = ((\"kabul\", \"mainland\", \"penis\", \"sherman\", \"EBxJQlXl\") + \"XnQFaytgpeI\").negligent2();" fullword ascii
    $s2  = "var prince = [solid, photographer,rocks,  \"\"+\".\"+(\"wayne\",\"shaped\",\"accumulates\",\"appalled\",\"admin\",\"passenger\"," ascii
    $s3  = "var beaker=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".negligent4())&&fence[\"c3RhdHVz\".negligent4()] +\"\"==\"MjAw\".negli" ascii
    $s4  = "var beaker=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".negligent4())&&fence[\"c3RhdHVz\".negligent4()] +\"\"==\"MjAw\".negli" ascii
    $s5  = "dysentery = dysentery+ prince.shift();" fullword ascii
    $s6  = "String.prototype.negligent2 = function () {" fullword ascii
    $s7  = "var prince = [solid, photographer,rocks,  \"\"+\".\"+(\"wayne\",\"shaped\",\"accumulates\",\"appalled\",\"admin\",\"passenger\"," ascii
    $s8  = "String.prototype.negligent4 = function() {" fullword ascii
    $s9  = "String.prototype.negligent = function () {" fullword ascii
    $s10 = "concord = ((\"ellen\", \"grill\", \"northeast\", \"carbine\", \"pUAfQRmB\") + \"MYDphv\").negligent2();" fullword ascii
    $s11 = "            fence[algeria]((\"corporeal\",\"commonly\",\"G\" + weasel) + (\"shoes\",\"covering\",\"heirloom\",\"impaired\",\"T\"" ascii
    $s12 = "            fence[algeria]((\"corporeal\",\"commonly\",\"G\" + weasel) + (\"shoes\",\"covering\",\"heirloom\",\"impaired\",\"T\"" ascii
    $s13 = "        guest[(\"hallowed\",\"extortion\",\"wrack\",\"warcraft\",\"dearborn\",\"description\",\"boils\",\"s\")+\"aveT\"+\"oF\"+" ascii
    $s14 = "specter = this;" fullword ascii
    $s15 = "  churn = [];" fullword ascii
    $s16 = "var fence = new tremendous(turkish[0]);" fullword ascii
    $s17 = "var falsify = 0;" fullword ascii
    $s18 = "function lycos(consciousness, oneness) {" fullword ascii
    $s19 = "var solid = \"QWN0aXZlWE9iamVjdA==\".negligent4();" fullword ascii
    $s20 = "var photographer =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".negligent4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}