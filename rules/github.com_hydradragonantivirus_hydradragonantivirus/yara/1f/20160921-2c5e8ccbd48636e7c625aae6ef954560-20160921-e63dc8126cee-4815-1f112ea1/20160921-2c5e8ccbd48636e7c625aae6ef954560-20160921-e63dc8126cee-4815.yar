rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_e63dc8126cee_4815 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s2 = "i\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s3 = "function fuck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}