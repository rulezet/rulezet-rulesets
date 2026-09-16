rule TTP_XOR_QUAD_CurrentVersionRun_516a {
  strings:
    $key_516a = { 02 05 [2] 26 0b [2] 0d 27 [2] 23 05 [2] 37 1e [2] 38 04 [2] 26 19 [2] 24 18 [2] 3f 1e [2] 23 19 [2] 3f 36 }

  condition:
    any of them
}