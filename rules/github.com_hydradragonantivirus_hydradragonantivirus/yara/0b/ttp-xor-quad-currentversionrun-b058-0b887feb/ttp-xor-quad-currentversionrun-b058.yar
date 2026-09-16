rule TTP_XOR_QUAD_CurrentVersionRun_b058 {
  strings:
    $key_b058 = { e3 37 [2] c7 39 [2] ec 15 [2] c2 37 [2] d6 2c [2] d9 36 [2] c7 2b [2] c5 2a [2] de 2c [2] c2 2b [2] de 04 }

  condition:
    any of them
}