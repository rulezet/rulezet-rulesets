rule TTP_XOR_QUAD_CurrentVersionRun_482a {
  strings:
    $key_482a = { 1b 45 [2] 3f 4b [2] 14 67 [2] 3a 45 [2] 2e 5e [2] 21 44 [2] 3f 59 [2] 3d 58 [2] 26 5e [2] 3a 59 [2] 26 76 }

  condition:
    any of them
}