rule TTP_XOR_QUAD_CurrentVersionRun_a3da {
  strings:
    $key_a3da = { f0 b5 [2] d4 bb [2] ff 97 [2] d1 b5 [2] c5 ae [2] ca b4 [2] d4 a9 [2] d6 a8 [2] cd ae [2] d1 a9 [2] cd 86 }

  condition:
    any of them
}