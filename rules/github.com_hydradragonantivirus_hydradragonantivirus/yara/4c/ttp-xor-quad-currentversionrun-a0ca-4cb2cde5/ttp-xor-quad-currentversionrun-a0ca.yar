rule TTP_XOR_QUAD_CurrentVersionRun_a0ca {
  strings:
    $key_a0ca = { f3 a5 [2] d7 ab [2] fc 87 [2] d2 a5 [2] c6 be [2] c9 a4 [2] d7 b9 [2] d5 b8 [2] ce be [2] d2 b9 [2] ce 96 }

  condition:
    any of them
}