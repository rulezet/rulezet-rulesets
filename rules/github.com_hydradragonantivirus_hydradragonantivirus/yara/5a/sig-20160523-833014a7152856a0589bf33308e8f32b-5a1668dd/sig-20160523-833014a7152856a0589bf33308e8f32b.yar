rule sig_20160523_833014a7152856a0589bf33308e8f32b {
  meta:
    description = "datamaliciousorder - file 20160523_833014a7152856a0589bf33308e8f32b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f853244638f7baa3ebaa2bf5792c34bdee29909493f8500032d38907e78be224"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = " + sdkfjksdjf8 + sdfjsdjhfhsd9 + sdfjsdjhfhs10, 'oghtuunzakkybilpjlxp.txt');                  var fso = new ActiveXObject(\"Scri" ascii
    $s3 = "lename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(ch" ascii
    $s4 = "            decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsfhsjdhfjhs7" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}