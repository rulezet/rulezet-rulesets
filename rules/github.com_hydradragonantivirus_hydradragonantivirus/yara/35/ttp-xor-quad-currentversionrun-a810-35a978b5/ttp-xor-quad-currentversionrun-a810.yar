rule TTP_XOR_QUAD_CurrentVersionRun_a810 {
  strings:
    $key_a810 = { fb 7f [2] df 71 [2] f4 5d [2] da 7f [2] ce 64 [2] c1 7e [2] df 63 [2] dd 62 [2] c6 64 [2] da 63 [2] c6 4c }

  condition:
    any of them
}