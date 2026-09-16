rule TTP_XOR_QUAD_CurrentVersionRun_b0c0 {
  strings:
    $key_b0c0 = { e3 af [2] c7 a1 [2] ec 8d [2] c2 af [2] d6 b4 [2] d9 ae [2] c7 b3 [2] c5 b2 [2] de b4 [2] c2 b3 [2] de 9c }

  condition:
    any of them
}