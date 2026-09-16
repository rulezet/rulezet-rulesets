rule TTP_XOR_QUAD_CurrentVersionRun_621a {
  strings:
    $key_621a = { 31 75 [2] 15 7b [2] 3e 57 [2] 10 75 [2] 04 6e [2] 0b 74 [2] 15 69 [2] 17 68 [2] 0c 6e [2] 10 69 [2] 0c 46 }

  condition:
    any of them
}