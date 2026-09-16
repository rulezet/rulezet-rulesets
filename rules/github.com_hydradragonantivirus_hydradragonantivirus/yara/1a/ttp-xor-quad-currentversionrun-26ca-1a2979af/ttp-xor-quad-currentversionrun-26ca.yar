rule TTP_XOR_QUAD_CurrentVersionRun_26ca {
  strings:
    $key_26ca = { 75 a5 [2] 51 ab [2] 7a 87 [2] 54 a5 [2] 40 be [2] 4f a4 [2] 51 b9 [2] 53 b8 [2] 48 be [2] 54 b9 [2] 48 96 }

  condition:
    any of them
}