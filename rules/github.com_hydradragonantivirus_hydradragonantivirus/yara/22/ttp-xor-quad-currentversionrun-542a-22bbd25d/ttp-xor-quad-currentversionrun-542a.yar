rule TTP_XOR_QUAD_CurrentVersionRun_542a {
  strings:
    $key_542a = { 07 45 [2] 23 4b [2] 08 67 [2] 26 45 [2] 32 5e [2] 3d 44 [2] 23 59 [2] 21 58 [2] 3a 5e [2] 26 59 [2] 3a 76 }

  condition:
    any of them
}