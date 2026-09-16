rule TTP_XOR_QUAD_CurrentVersionRun_631a {
  strings:
    $key_631a = { 30 75 [2] 14 7b [2] 3f 57 [2] 11 75 [2] 05 6e [2] 0a 74 [2] 14 69 [2] 16 68 [2] 0d 6e [2] 11 69 [2] 0d 46 }

  condition:
    any of them
}