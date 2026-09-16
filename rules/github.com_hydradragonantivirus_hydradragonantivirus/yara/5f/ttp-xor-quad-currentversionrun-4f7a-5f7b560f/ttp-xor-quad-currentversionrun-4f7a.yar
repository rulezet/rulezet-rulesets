rule TTP_XOR_QUAD_CurrentVersionRun_4f7a {
  strings:
    $key_4f7a = { 1c 15 [2] 38 1b [2] 13 37 [2] 3d 15 [2] 29 0e [2] 26 14 [2] 38 09 [2] 3a 08 [2] 21 0e [2] 3d 09 [2] 21 26 }

  condition:
    any of them
}