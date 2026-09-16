rule TTP_XOR_QUAD_CurrentVersionRun_257f {
  strings:
    $key_257f = { 76 10 [2] 52 1e [2] 79 32 [2] 57 10 [2] 43 0b [2] 4c 11 [2] 52 0c [2] 50 0d [2] 4b 0b [2] 57 0c [2] 4b 23 }

  condition:
    any of them
}