rule TTP_XOR_QUAD_CurrentVersionRun_b138 {
  strings:
    $key_b138 = { e2 57 [2] c6 59 [2] ed 75 [2] c3 57 [2] d7 4c [2] d8 56 [2] c6 4b [2] c4 4a [2] df 4c [2] c3 4b [2] df 64 }

  condition:
    any of them
}