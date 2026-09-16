rule TTP_XOR_QUAD_CurrentVersionRun_a0c1 {
  strings:
    $key_a0c1 = { f3 ae [2] d7 a0 [2] fc 8c [2] d2 ae [2] c6 b5 [2] c9 af [2] d7 b2 [2] d5 b3 [2] ce b5 [2] d2 b2 [2] ce 9d }

  condition:
    any of them
}