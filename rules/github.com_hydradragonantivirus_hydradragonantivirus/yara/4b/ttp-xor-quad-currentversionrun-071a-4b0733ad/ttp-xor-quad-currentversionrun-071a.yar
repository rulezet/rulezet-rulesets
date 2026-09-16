rule TTP_XOR_QUAD_CurrentVersionRun_071a {
  strings:
    $key_071a = { 54 75 [2] 70 7b [2] 5b 57 [2] 75 75 [2] 61 6e [2] 6e 74 [2] 70 69 [2] 72 68 [2] 69 6e [2] 75 69 [2] 69 46 }

  condition:
    any of them
}