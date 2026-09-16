rule TTP_XOR_QUAD_CurrentVersionRun_282b {
  strings:
    $key_282b = { 7b 44 [2] 5f 4a [2] 74 66 [2] 5a 44 [2] 4e 5f [2] 41 45 [2] 5f 58 [2] 5d 59 [2] 46 5f [2] 5a 58 [2] 46 77 }

  condition:
    any of them
}