rule TTP_XOR_QUAD_CurrentVersionRun_516b {
  strings:
    $key_516b = { 02 04 [2] 26 0a [2] 0d 26 [2] 23 04 [2] 37 1f [2] 38 05 [2] 26 18 [2] 24 19 [2] 3f 1f [2] 23 18 [2] 3f 37 }

  condition:
    any of them
}