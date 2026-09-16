rule TTP_XOR_QUAD_CurrentVersionRun_b67b {
  strings:
    $key_b67b = { e5 14 [2] c1 1a [2] ea 36 [2] c4 14 [2] d0 0f [2] df 15 [2] c1 08 [2] c3 09 [2] d8 0f [2] c4 08 [2] d8 27 }

  condition:
    any of them
}