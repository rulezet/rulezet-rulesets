rule TTP_XOR_QUAD_CurrentVersionRun_b11e {
  strings:
    $key_b11e = { e2 71 [2] c6 7f [2] ed 53 [2] c3 71 [2] d7 6a [2] d8 70 [2] c6 6d [2] c4 6c [2] df 6a [2] c3 6d [2] df 42 }

  condition:
    any of them
}