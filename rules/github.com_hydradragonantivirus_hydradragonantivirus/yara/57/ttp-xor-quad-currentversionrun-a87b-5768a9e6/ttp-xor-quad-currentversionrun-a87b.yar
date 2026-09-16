rule TTP_XOR_QUAD_CurrentVersionRun_a87b {
  strings:
    $key_a87b = { fb 14 [2] df 1a [2] f4 36 [2] da 14 [2] ce 0f [2] c1 15 [2] df 08 [2] dd 09 [2] c6 0f [2] da 08 [2] c6 27 }

  condition:
    any of them
}