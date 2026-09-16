rule TTP_XOR_QUAD_CurrentVersionRun_55ca {
  strings:
    $key_55ca = { 06 a5 [2] 22 ab [2] 09 87 [2] 27 a5 [2] 33 be [2] 3c a4 [2] 22 b9 [2] 20 b8 [2] 3b be [2] 27 b9 [2] 3b 96 }

  condition:
    any of them
}