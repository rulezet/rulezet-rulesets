rule TTP_XOR_QUAD_CurrentVersionRun_4f6a {
  strings:
    $key_4f6a = { 1c 05 [2] 38 0b [2] 13 27 [2] 3d 05 [2] 29 1e [2] 26 04 [2] 38 19 [2] 3a 18 [2] 21 1e [2] 3d 19 [2] 21 36 }

  condition:
    any of them
}