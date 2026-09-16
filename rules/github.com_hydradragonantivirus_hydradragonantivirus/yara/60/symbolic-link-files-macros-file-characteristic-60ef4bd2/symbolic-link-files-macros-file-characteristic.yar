rule Symbolic_Link_Files_Macros_File_Characteristic {
  meta:
    Author      = "InQuest Labs"
    URL         = "https://github.com/InQuest/yara-rules/edit/master/Symbolic_Link_Files_Macros_File_Characteristic.rule"
    Description = "This signature detects Symbolic Link (SLK) files that contain Excel 4.0 macros. While not inherently malicious, these SLK files can be used used by attackers to evade detection and deliver malicious payloads."
    References  = "https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/"

  strings:
    $magic = "ID;P"

    $re1 = /\x0aO;E[\r\n]/ nocase
  

      
  

  condition:
    $magic in (0..100) and all of ($re*)
}