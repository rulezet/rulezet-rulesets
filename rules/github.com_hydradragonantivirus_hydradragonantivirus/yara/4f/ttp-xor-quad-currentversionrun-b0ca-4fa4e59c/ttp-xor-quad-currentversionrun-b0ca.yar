rule TTP_XOR_QUAD_CurrentVersionRun_b0ca {
  strings:
    $key_b0ca = { e3 a5 [2] c7 ab [2] ec 87 [2] c2 a5 [2] d6 be [2] d9 a4 [2] c7 b9 [2] c5 b8 [2] de be [2] c2 b9 [2] de 96 }

  condition:
    any of them
}