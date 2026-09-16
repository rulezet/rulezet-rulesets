rule TTP_XOR_QUAD_CurrentVersionRun_710a {
  strings:
    $key_710a = { 22 65 [2] 06 6b [2] 2d 47 [2] 03 65 [2] 17 7e [2] 18 64 [2] 06 79 [2] 04 78 [2] 1f 7e [2] 03 79 [2] 1f 56 }

  condition:
    any of them
}