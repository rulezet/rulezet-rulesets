rule TTP_XOR_QUAD_CurrentVersionRun_b6e2 {
  strings:
    $key_b6e2 = { e5 8d [2] c1 83 [2] ea af [2] c4 8d [2] d0 96 [2] df 8c [2] c1 91 [2] c3 90 [2] d8 96 [2] c4 91 [2] d8 be }

  condition:
    any of them
}