rule TTP_XOR_QUAD_CurrentVersionRun_482d {
  strings:
    $key_482d = { 1b 42 [2] 3f 4c [2] 14 60 [2] 3a 42 [2] 2e 59 [2] 21 43 [2] 3f 5e [2] 3d 5f [2] 26 59 [2] 3a 5e [2] 26 71 }

  condition:
    any of them
}