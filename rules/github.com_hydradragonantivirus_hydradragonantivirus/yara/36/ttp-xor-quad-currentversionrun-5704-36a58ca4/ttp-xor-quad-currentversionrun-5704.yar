rule TTP_XOR_QUAD_CurrentVersionRun_5704 {
  strings:
    $key_5704 = { 04 6b [2] 20 65 [2] 0b 49 [2] 25 6b [2] 31 70 [2] 3e 6a [2] 20 77 [2] 22 76 [2] 39 70 [2] 25 77 [2] 39 58 }

  condition:
    any of them
}