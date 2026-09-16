rule TTP_XOR_QUAD_CurrentVersionRun_621b {
  strings:
    $key_621b = { 31 74 [2] 15 7a [2] 3e 56 [2] 10 74 [2] 04 6f [2] 0b 75 [2] 15 68 [2] 17 69 [2] 0c 6f [2] 10 68 [2] 0c 47 }

  condition:
    any of them
}