rule TTP_XOR_QUAD_CurrentVersionRun_e2ca {
  strings:
    $key_e2ca = { b1 a5 [2] 95 ab [2] be 87 [2] 90 a5 [2] 84 be [2] 8b a4 [2] 95 b9 [2] 97 b8 [2] 8c be [2] 90 b9 [2] 8c 96 }

  condition:
    any of them
}