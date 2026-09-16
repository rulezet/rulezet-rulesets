rule TTP_XOR_QUAD_CurrentVersionRun_a871 {
  strings:
    $key_a871 = { fb 1e [2] df 10 [2] f4 3c [2] da 1e [2] ce 05 [2] c1 1f [2] df 02 [2] dd 03 [2] c6 05 [2] da 02 [2] c6 2d }

  condition:
    any of them
}