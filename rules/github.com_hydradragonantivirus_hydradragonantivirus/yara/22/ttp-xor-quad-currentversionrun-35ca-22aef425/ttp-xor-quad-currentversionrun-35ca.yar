rule TTP_XOR_QUAD_CurrentVersionRun_35ca {
  strings:
    $key_35ca = { 66 a5 [2] 42 ab [2] 69 87 [2] 47 a5 [2] 53 be [2] 5c a4 [2] 42 b9 [2] 40 b8 [2] 5b be [2] 47 b9 [2] 5b 96 }

  condition:
    any of them
}