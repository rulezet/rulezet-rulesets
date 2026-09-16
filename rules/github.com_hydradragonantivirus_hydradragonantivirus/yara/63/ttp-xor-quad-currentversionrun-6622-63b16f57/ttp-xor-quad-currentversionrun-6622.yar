rule TTP_XOR_QUAD_CurrentVersionRun_6622 {
  strings:
    $key_6622 = { 35 4d [2] 11 43 [2] 3a 6f [2] 14 4d [2] 00 56 [2] 0f 4c [2] 11 51 [2] 13 50 [2] 08 56 [2] 14 51 [2] 08 7e }

  condition:
    any of them
}