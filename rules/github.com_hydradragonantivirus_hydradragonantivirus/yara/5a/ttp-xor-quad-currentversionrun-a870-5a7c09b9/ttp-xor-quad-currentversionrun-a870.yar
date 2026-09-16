rule TTP_XOR_QUAD_CurrentVersionRun_a870 {
  strings:
    $key_a870 = { fb 1f [2] df 11 [2] f4 3d [2] da 1f [2] ce 04 [2] c1 1e [2] df 03 [2] dd 02 [2] c6 04 [2] da 03 [2] c6 2c }

  condition:
    any of them
}