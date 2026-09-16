rule TTP_XOR_QUAD_CurrentVersionRun_1311 {
  strings:
    $key_1311 = { 40 7e [2] 64 70 [2] 4f 5c [2] 61 7e [2] 75 65 [2] 7a 7f [2] 64 62 [2] 66 63 [2] 7d 65 [2] 61 62 [2] 7d 4d }

  condition:
    any of them
}