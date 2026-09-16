rule TTP_XOR_QUAD_CurrentVersionRun_b1e3 {
  strings:
    $key_b1e3 = { e2 8c [2] c6 82 [2] ed ae [2] c3 8c [2] d7 97 [2] d8 8d [2] c6 90 [2] c4 91 [2] df 97 [2] c3 90 [2] df bf }

  condition:
    any of them
}