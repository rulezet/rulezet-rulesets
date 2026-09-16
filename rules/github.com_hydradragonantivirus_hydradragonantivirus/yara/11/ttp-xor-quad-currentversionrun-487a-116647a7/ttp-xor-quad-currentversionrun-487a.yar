rule TTP_XOR_QUAD_CurrentVersionRun_487a {
  strings:
    $key_487a = { 1b 15 [2] 3f 1b [2] 14 37 [2] 3a 15 [2] 2e 0e [2] 21 14 [2] 3f 09 [2] 3d 08 [2] 26 0e [2] 3a 09 [2] 26 26 }

  condition:
    any of them
}