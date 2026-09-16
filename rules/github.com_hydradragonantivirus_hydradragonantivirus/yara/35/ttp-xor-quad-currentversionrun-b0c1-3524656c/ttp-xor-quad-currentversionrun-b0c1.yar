rule TTP_XOR_QUAD_CurrentVersionRun_b0c1 {
  strings:
    $key_b0c1 = { e3 ae [2] c7 a0 [2] ec 8c [2] c2 ae [2] d6 b5 [2] d9 af [2] c7 b2 [2] c5 b3 [2] de b5 [2] c2 b2 [2] de 9d }

  condition:
    any of them
}