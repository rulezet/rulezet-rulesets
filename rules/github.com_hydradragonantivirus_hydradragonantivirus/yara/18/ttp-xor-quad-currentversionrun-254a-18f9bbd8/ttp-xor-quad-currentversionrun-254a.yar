rule TTP_XOR_QUAD_CurrentVersionRun_254a {
  strings:
    $key_254a = { 76 25 [2] 52 2b [2] 79 07 [2] 57 25 [2] 43 3e [2] 4c 24 [2] 52 39 [2] 50 38 [2] 4b 3e [2] 57 39 [2] 4b 16 }

  condition:
    any of them
}