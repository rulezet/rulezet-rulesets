rule TTP_XOR_QUAD_CurrentVersionRun_b102 {
  strings:
    $key_b102 = { e2 6d [2] c6 63 [2] ed 4f [2] c3 6d [2] d7 76 [2] d8 6c [2] c6 71 [2] c4 70 [2] df 76 [2] c3 71 [2] df 5e }

  condition:
    any of them
}