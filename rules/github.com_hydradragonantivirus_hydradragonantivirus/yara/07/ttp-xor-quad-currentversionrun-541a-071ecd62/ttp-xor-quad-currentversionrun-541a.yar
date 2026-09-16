rule TTP_XOR_QUAD_CurrentVersionRun_541a {
  strings:
    $key_541a = { 07 75 [2] 23 7b [2] 08 57 [2] 26 75 [2] 32 6e [2] 3d 74 [2] 23 69 [2] 21 68 [2] 3a 6e [2] 26 69 [2] 3a 46 }

  condition:
    any of them
}