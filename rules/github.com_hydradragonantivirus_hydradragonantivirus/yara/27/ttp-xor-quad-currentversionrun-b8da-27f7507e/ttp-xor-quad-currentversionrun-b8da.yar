rule TTP_XOR_QUAD_CurrentVersionRun_b8da {
  strings:
    $key_b8da = { eb b5 [2] cf bb [2] e4 97 [2] ca b5 [2] de ae [2] d1 b4 [2] cf a9 [2] cd a8 [2] d6 ae [2] ca a9 [2] d6 86 }

  condition:
    any of them
}