rule TTP_XOR_QUAD_CurrentVersionRun_b018 {
  strings:
    $key_b018 = { e3 77 [2] c7 79 [2] ec 55 [2] c2 77 [2] d6 6c [2] d9 76 [2] c7 6b [2] c5 6a [2] de 6c [2] c2 6b [2] de 44 }

  condition:
    any of them
}