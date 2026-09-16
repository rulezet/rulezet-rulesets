rule TTP_XOR_QUAD_CurrentVersionRun_1a1d {
  strings:
    $key_1a1d = { 49 72 [2] 6d 7c [2] 46 50 [2] 68 72 [2] 7c 69 [2] 73 73 [2] 6d 6e [2] 6f 6f [2] 74 69 [2] 68 6e [2] 74 41 }

  condition:
    any of them
}