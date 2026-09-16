rule TTP_XOR_QUAD_CurrentVersionRun_482c {
  strings:
    $key_482c = { 1b 43 [2] 3f 4d [2] 14 61 [2] 3a 43 [2] 2e 58 [2] 21 42 [2] 3f 5f [2] 3d 5e [2] 26 58 [2] 3a 5f [2] 26 70 }

  condition:
    any of them
}