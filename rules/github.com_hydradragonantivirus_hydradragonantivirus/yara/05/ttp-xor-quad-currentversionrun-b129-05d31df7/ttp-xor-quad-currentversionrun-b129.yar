rule TTP_XOR_QUAD_CurrentVersionRun_b129 {
  strings:
    $key_b129 = { e2 46 [2] c6 48 [2] ed 64 [2] c3 46 [2] d7 5d [2] d8 47 [2] c6 5a [2] c4 5b [2] df 5d [2] c3 5a [2] df 75 }

  condition:
    any of them
}