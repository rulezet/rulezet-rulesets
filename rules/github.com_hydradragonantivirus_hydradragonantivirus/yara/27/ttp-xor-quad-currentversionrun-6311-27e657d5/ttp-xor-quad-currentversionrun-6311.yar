rule TTP_XOR_QUAD_CurrentVersionRun_6311 {
  strings:
    $key_6311 = { 30 7e [2] 14 70 [2] 3f 5c [2] 11 7e [2] 05 65 [2] 0a 7f [2] 14 62 [2] 16 63 [2] 0d 65 [2] 11 62 [2] 0d 4d }

  condition:
    any of them
}