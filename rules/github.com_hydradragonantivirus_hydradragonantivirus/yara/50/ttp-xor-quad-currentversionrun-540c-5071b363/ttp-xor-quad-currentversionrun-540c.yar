rule TTP_XOR_QUAD_CurrentVersionRun_540c {
  strings:
    $key_540c = { 07 63 [2] 23 6d [2] 08 41 [2] 26 63 [2] 32 78 [2] 3d 62 [2] 23 7f [2] 21 7e [2] 3a 78 [2] 26 7f [2] 3a 50 }

  condition:
    any of them
}