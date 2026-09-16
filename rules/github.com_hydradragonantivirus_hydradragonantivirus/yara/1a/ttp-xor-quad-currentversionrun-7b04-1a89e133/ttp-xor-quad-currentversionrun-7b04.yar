rule TTP_XOR_QUAD_CurrentVersionRun_7b04 {
  strings:
    $key_7b04 = { 28 6b [2] 0c 65 [2] 27 49 [2] 09 6b [2] 1d 70 [2] 12 6a [2] 0c 77 [2] 0e 76 [2] 15 70 [2] 09 77 [2] 15 58 }

  condition:
    any of them
}