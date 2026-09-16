rule TTP_XOR_QUAD_CurrentVersionRun_7b0a {
  strings:
    $key_7b0a = { 28 65 [2] 0c 6b [2] 27 47 [2] 09 65 [2] 1d 7e [2] 12 64 [2] 0c 79 [2] 0e 78 [2] 15 7e [2] 09 79 [2] 15 56 }

  condition:
    any of them
}