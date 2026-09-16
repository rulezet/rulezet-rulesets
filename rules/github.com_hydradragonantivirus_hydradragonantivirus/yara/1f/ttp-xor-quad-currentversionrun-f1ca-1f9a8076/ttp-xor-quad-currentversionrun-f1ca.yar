rule TTP_XOR_QUAD_CurrentVersionRun_f1ca {
  strings:
    $key_f1ca = { a2 a5 [2] 86 ab [2] ad 87 [2] 83 a5 [2] 97 be [2] 98 a4 [2] 86 b9 [2] 84 b8 [2] 9f be [2] 83 b9 [2] 9f 96 }

  condition:
    any of them
}