rule sig_20160523_e3b15e40581b672d12f9f8603737dc51 {
  meta:
    description = "datamaliciousorder - file 20160523_e3b15e40581b672d12f9f8603737dc51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8be37f3a5c4938fb5e4a70ecff62779f1d1e987790e87780a8cd23e58d38445"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "= fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(check);                       " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}