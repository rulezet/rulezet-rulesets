rule TTP_XOR_QUAD_CurrentVersionRun_480d {
  strings:
    $key_480d = { 1b 62 [2] 3f 6c [2] 14 40 [2] 3a 62 [2] 2e 79 [2] 21 63 [2] 3f 7e [2] 3d 7f [2] 26 79 [2] 3a 7e [2] 26 51 }

  condition:
    any of them
}