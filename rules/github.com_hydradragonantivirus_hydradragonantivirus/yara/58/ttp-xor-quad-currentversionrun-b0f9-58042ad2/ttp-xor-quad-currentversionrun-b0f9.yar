rule TTP_XOR_QUAD_CurrentVersionRun_b0f9 {
  strings:
    $key_b0f9 = { e3 96 [2] c7 98 [2] ec b4 [2] c2 96 [2] d6 8d [2] d9 97 [2] c7 8a [2] c5 8b [2] de 8d [2] c2 8a [2] de a5 }

  condition:
    any of them
}