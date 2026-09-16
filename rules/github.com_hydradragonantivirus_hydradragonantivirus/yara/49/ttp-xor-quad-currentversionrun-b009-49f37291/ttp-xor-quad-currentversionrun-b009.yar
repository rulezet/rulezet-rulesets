rule TTP_XOR_QUAD_CurrentVersionRun_b009 {
  strings:
    $key_b009 = { e3 66 [2] c7 68 [2] ec 44 [2] c2 66 [2] d6 7d [2] d9 67 [2] c7 7a [2] c5 7b [2] de 7d [2] c2 7a [2] de 55 }

  condition:
    any of them
}