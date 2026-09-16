rule TTP_XOR_QUAD_CurrentVersionRun_6611 {
  strings:
    $key_6611 = { 35 7e [2] 11 70 [2] 3a 5c [2] 14 7e [2] 00 65 [2] 0f 7f [2] 11 62 [2] 13 63 [2] 08 65 [2] 14 62 [2] 08 4d }

  condition:
    any of them
}