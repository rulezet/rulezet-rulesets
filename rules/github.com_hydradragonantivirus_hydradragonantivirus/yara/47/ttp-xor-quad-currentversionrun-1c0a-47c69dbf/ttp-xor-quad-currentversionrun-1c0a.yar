rule TTP_XOR_QUAD_CurrentVersionRun_1c0a {
  strings:
    $key_1c0a = { 4f 65 [2] 6b 6b [2] 40 47 [2] 6e 65 [2] 7a 7e [2] 75 64 [2] 6b 79 [2] 69 78 [2] 72 7e [2] 6e 79 [2] 72 56 }

  condition:
    any of them
}