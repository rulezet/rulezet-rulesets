rule TTP_XOR_QUAD_CurrentVersionRun_a80c {
  strings:
    $key_a80c = { fb 63 [2] df 6d [2] f4 41 [2] da 63 [2] ce 78 [2] c1 62 [2] df 7f [2] dd 7e [2] c6 78 [2] da 7f [2] c6 50 }

  condition:
    any of them
}