rule TTP_XOR_QUAD_CurrentVersionRun_a80b {
  strings:
    $key_a80b = { fb 64 [2] df 6a [2] f4 46 [2] da 64 [2] ce 7f [2] c1 65 [2] df 78 [2] dd 79 [2] c6 7f [2] da 78 [2] c6 57 }

  condition:
    any of them
}