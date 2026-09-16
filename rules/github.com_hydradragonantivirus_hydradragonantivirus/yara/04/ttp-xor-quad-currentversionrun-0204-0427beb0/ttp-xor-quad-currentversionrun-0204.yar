rule TTP_XOR_QUAD_CurrentVersionRun_0204 {
  strings:
    $key_0204 = { 51 6b [2] 75 65 [2] 5e 49 [2] 70 6b [2] 64 70 [2] 6b 6a [2] 75 77 [2] 77 76 [2] 6c 70 [2] 70 77 [2] 6c 58 }

  condition:
    any of them
}