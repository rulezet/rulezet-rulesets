rule TTP_XOR_QUAD_CurrentVersionRun_216a {
  strings:
    $key_216a = { 72 05 [2] 56 0b [2] 7d 27 [2] 53 05 [2] 47 1e [2] 48 04 [2] 56 19 [2] 54 18 [2] 4f 1e [2] 53 19 [2] 4f 36 }

  condition:
    any of them
}