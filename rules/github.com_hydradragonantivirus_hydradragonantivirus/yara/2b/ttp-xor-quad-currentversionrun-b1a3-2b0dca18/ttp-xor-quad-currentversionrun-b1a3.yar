rule TTP_XOR_QUAD_CurrentVersionRun_b1a3 {
  strings:
    $key_b1a3 = { e2 cc [2] c6 c2 [2] ed ee [2] c3 cc [2] d7 d7 [2] d8 cd [2] c6 d0 [2] c4 d1 [2] df d7 [2] c3 d0 [2] df ff }

  condition:
    any of them
}