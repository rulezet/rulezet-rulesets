rule TTP_XOR_QUAD_CurrentVersionRun_532a {
  strings:
    $key_532a = { 00 45 [2] 24 4b [2] 0f 67 [2] 21 45 [2] 35 5e [2] 3a 44 [2] 24 59 [2] 26 58 [2] 3d 5e [2] 21 59 [2] 3d 76 }

  condition:
    any of them
}