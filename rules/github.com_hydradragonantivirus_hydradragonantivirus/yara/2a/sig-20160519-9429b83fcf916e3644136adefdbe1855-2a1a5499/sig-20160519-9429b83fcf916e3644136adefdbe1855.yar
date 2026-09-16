rule sig_20160519_9429b83fcf916e3644136adefdbe1855 {
  meta:
    description = "datamaliciousorder - file 20160519_9429b83fcf916e3644136adefdbe1855.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bc421ebc08f4c8af811358dd7a2d0ad3e539711d30930435b98bf8240b64de3"

  strings:
    $s1  = "var meeting = [lethargy, ignominy,seminars,  \"\"+\".\"+(\"events\",\"marred\",\"ludlow\",\"bronze\",\"maldives\",\"regent\",\"c" ascii
    $s2  = "function imports(compile, troubadour) {" fullword ascii
    $s3  = "var proverbial=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hindostan4())&&dispel[\"c3RhdHVz\".hindostan4()] +\"\"==\"MjAw\"." ascii
    $s4  = "var proverbial=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hindostan4())&&dispel[\"c3RhdHVz\".hindostan4()] +\"\"==\"MjAw\"." ascii
    $s5  = "weasel = ((\"elaboration\", \"oblation\", \"playwright\", \"denied\", \"EKlPVzDXUaFi\") + \"WDSFNFAkOA\").hindostan2();" fullword ascii
    $s6  = "decided = decided+ meeting.shift();" fullword ascii
    $s7  = "twice = ((\"editorials\", \"batman\", \"closing\", \"found\", \"builder\", \"unfortunately\", \"ssJdTXAbevhK\") + \"MBbmGTlGh\")" ascii
    $s8  = "String.prototype.hindostan4 = function() {" fullword ascii
    $s9  = "var refrigerator = meeting.pop().split(\">\");" fullword ascii
    $s10 = "        var supporter = new blemish(((\"terminology\",\"equality\",\"florence\",\"digest\",\"atone\",\"argumentative\",\"module" ascii
    $s11 = "String.prototype.hindostan2 = function () {" fullword ascii
    $s12 = "        var supporter = new blemish(((\"terminology\",\"equality\",\"florence\",\"digest\",\"atone\",\"argumentative\",\"module" ascii
    $s13 = "String.prototype.hindostan = function () {" fullword ascii
    $s14 = ", compile, false);" fullword ascii
    $s15 = "        supporter[(hospitals + \"o\"+(\"woeful\",\"reflects\",\"journalism\",\"parking\",\"phillips\",\"requiring\",\"darius\"," ascii
    $s16 = "        supporter[(hospitals + \"o\"+(\"woeful\",\"reflects\",\"journalism\",\"parking\",\"phillips\",\"requiring\",\"darius\"," ascii
    $s17 = "            dispel[inquisitiveness]((\"tanned\",\"complication\",\"G\" + weasel) + (\"tartar\",\"michel\",\"importunate\",\"engi" ascii
    $s18 = "            dispel[inquisitiveness]((\"tanned\",\"complication\",\"G\" + weasel) + (\"tartar\",\"michel\",\"importunate\",\"engi" ascii
    $s19 = "var dispel = new blemish(refrigerator[0]);" fullword ascii
    $s20 = "var lethargy = \"QWhabitatN0aXZhabitatlWE9iahabitatmVjdA=habitat=\".hindostan4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}