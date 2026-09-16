rule TTP_XOR_QUAD_CurrentVersionRun_1a1a {
  strings:
    $key_1a1a = { 49 75 [2] 6d 7b [2] 46 57 [2] 68 75 [2] 7c 6e [2] 73 74 [2] 6d 69 [2] 6f 68 [2] 74 6e [2] 68 69 [2] 74 46 }

  condition:
    any of them
}