rule sig_20160523_581143c88e7675e644d0272eacac4ad2 {
  meta:
    description = "datamaliciousorder - file 20160523_581143c88e7675e644d0272eacac4ad2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58cf2845db2e51f8497fcdbae425910aa8ca4abf47d7a490a970ae4cba692a32"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = " + sdkfjksdjf8 + sdfjsdjhfhsd9 + sdfjsdjhfhs10, 'vtcugeeiagdfpxlbsxco.txt');                  var fso = new ActiveXObject(\"Scri" ascii
    $s3 = "lename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(ch" ascii
    $s4 = "            decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsfhsjdhfjhs7" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}