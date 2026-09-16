rule TTP_XOR_QUAD_CurrentVersionRun_6d2b {
  strings:
    $key_6d2b = { 3e 44 [2] 1a 4a [2] 31 66 [2] 1f 44 [2] 0b 5f [2] 04 45 [2] 1a 58 [2] 18 59 [2] 03 5f [2] 1f 58 [2] 03 77 }

  condition:
    any of them
}