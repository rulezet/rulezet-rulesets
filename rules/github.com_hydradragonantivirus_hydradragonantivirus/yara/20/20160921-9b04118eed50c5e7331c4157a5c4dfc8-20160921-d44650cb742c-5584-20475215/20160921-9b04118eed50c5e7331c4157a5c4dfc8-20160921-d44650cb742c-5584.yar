rule _20160921_9b04118eed50c5e7331c4157a5c4dfc8_20160921_d44650cb742c_5584 {
  meta:
    description = "datamaliciousorder - from files 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash2       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})" ascii
    $s2 = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck" ascii
    $s3 = "n fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s4 = "TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(functi" ascii
    $s5 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}