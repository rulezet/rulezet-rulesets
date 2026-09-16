rule TTP_XOR_QUAD_CurrentVersionRun_a09d {
  strings:
    $key_a09d = { f3 f2 [2] d7 fc [2] fc d0 [2] d2 f2 [2] c6 e9 [2] c9 f3 [2] d7 ee [2] d5 ef [2] ce e9 [2] d2 ee [2] ce c1 }

  condition:
    any of them
}