rule TTP_XOR_QUAD_CurrentVersionRun_dc77 {
  strings:
    $key_dc77 = { 8f 18 [2] ab 16 [2] 80 3a [2] ae 18 [2] ba 03 [2] b5 19 [2] ab 04 [2] a9 05 [2] b2 03 [2] ae 04 [2] b2 2b }

  condition:
    any of them
}