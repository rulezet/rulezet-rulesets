rule TTP_XOR_QUAD_CurrentVersionRun_a0d0 {
  strings:
    $key_a0d0 = { f3 bf [2] d7 b1 [2] fc 9d [2] d2 bf [2] c6 a4 [2] c9 be [2] d7 a3 [2] d5 a2 [2] ce a4 [2] d2 a3 [2] ce 8c }

  condition:
    any of them
}