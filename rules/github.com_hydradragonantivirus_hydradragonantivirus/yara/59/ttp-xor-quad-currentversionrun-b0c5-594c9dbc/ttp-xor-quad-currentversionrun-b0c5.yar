rule TTP_XOR_QUAD_CurrentVersionRun_b0c5 {
  strings:
    $key_b0c5 = { e3 aa [2] c7 a4 [2] ec 88 [2] c2 aa [2] d6 b1 [2] d9 ab [2] c7 b6 [2] c5 b7 [2] de b1 [2] c2 b6 [2] de 99 }

  condition:
    any of them
}