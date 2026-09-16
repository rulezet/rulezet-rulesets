rule TTP_XOR_QUAD_CurrentVersionRun_6612 {
  strings:
    $key_6612 = { 35 7d [2] 11 73 [2] 3a 5f [2] 14 7d [2] 00 66 [2] 0f 7c [2] 11 61 [2] 13 60 [2] 08 66 [2] 14 61 [2] 08 4e }

  condition:
    any of them
}