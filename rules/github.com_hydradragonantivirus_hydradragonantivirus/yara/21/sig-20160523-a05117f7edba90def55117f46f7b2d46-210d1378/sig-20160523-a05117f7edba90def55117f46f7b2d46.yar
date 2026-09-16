rule sig_20160523_a05117f7edba90def55117f46f7b2d46 {
  meta:
    description = "datamaliciousorder - file 20160523_a05117f7edba90def55117f46f7b2d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3c61192b1e8c8dfaf491f28b200e1e4b068eea30012919c902fd29f5fbef43a"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "           var check = ts.ReadAll();                 eval(check);                               ts.Close();                     " ascii
    $s3 = "3OS5leGUnLCAxKX1jYXRjaChlKXt9OyAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}