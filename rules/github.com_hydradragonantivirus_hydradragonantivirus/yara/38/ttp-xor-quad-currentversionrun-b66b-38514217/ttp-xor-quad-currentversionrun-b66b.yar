rule TTP_XOR_QUAD_CurrentVersionRun_b66b {
  strings:
    $key_b66b = { e5 04 [2] c1 0a [2] ea 26 [2] c4 04 [2] d0 1f [2] df 05 [2] c1 18 [2] c3 19 [2] d8 1f [2] c4 18 [2] d8 37 }

  condition:
    any of them
}