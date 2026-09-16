rule TTP_XOR_QUAD_CurrentVersionRun_a84b {
  strings:
    $key_a84b = { fb 24 [2] df 2a [2] f4 06 [2] da 24 [2] ce 3f [2] c1 25 [2] df 38 [2] dd 39 [2] c6 3f [2] da 38 [2] c6 17 }

  condition:
    any of them
}