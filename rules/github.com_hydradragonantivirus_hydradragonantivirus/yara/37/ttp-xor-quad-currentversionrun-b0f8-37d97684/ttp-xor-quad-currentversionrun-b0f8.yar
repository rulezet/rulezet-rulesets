rule TTP_XOR_QUAD_CurrentVersionRun_b0f8 {
  strings:
    $key_b0f8 = { e3 97 [2] c7 99 [2] ec b5 [2] c2 97 [2] d6 8c [2] d9 96 [2] c7 8b [2] c5 8a [2] de 8c [2] c2 8b [2] de a4 }

  condition:
    any of them
}