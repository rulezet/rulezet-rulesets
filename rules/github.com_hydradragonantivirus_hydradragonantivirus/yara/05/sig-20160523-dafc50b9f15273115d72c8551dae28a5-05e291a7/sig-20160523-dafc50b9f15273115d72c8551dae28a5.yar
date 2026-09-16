rule sig_20160523_dafc50b9f15273115d72c8551dae28a5 {
  meta:
    description = "datamaliciousorder - file 20160523_dafc50b9f15273115d72c8551dae28a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02863a82d064e3f28a2e4459b4e0b95684a153daba4ed6cf43ff075f4b442701"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = " + sdkfjksdjf8 + sdfjsdjhfhsd9 + sdfjsdjhfhs10, 'obbrzodczxhvypjtyjqu.txt');                  var fso = new ActiveXObject(\"Scri" ascii
    $s3 = "lename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(ch" ascii
    $s4 = "            decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsfhsjdhfjhs7" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}