rule TTP_XOR_QUAD_CurrentVersionRun_2b17 {
  strings:
    $key_2b17 = { 78 78 [2] 5c 76 [2] 77 5a [2] 59 78 [2] 4d 63 [2] 42 79 [2] 5c 64 [2] 5e 65 [2] 45 63 [2] 59 64 [2] 45 4b }

  condition:
    any of them
}