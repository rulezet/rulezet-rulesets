rule TTP_XOR_QUAD_CurrentVersionRun_fa1a {
  strings:
    $key_fa1a = { a9 75 [2] 8d 7b [2] a6 57 [2] 88 75 [2] 9c 6e [2] 93 74 [2] 8d 69 [2] 8f 68 [2] 94 6e [2] 88 69 [2] 94 46 }

  condition:
    any of them
}