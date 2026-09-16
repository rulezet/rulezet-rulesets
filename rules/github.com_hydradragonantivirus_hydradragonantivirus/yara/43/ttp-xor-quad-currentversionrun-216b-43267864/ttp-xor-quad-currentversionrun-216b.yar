rule TTP_XOR_QUAD_CurrentVersionRun_216b {
  strings:
    $key_216b = { 72 04 [2] 56 0a [2] 7d 26 [2] 53 04 [2] 47 1f [2] 48 05 [2] 56 18 [2] 54 19 [2] 4f 1f [2] 53 18 [2] 4f 37 }

  condition:
    any of them
}