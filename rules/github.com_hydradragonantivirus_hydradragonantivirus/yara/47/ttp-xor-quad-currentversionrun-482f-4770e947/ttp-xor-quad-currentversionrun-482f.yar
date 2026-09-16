rule TTP_XOR_QUAD_CurrentVersionRun_482f {
  strings:
    $key_482f = { 1b 40 [2] 3f 4e [2] 14 62 [2] 3a 40 [2] 2e 5b [2] 21 41 [2] 3f 5c [2] 3d 5d [2] 26 5b [2] 3a 5c [2] 26 73 }

  condition:
    any of them
}