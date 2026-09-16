rule TTP_XOR_QUAD_CurrentVersionRun_b074 {
  strings:
    $key_b074 = { e3 1b [2] c7 15 [2] ec 39 [2] c2 1b [2] d6 00 [2] d9 1a [2] c7 07 [2] c5 06 [2] de 00 [2] c2 07 [2] de 28 }

  condition:
    any of them
}