rule TTP_XOR_QUAD_CurrentVersionRun_4f20 {
  strings:
    $key_4f20 = { 1c 4f [2] 38 41 [2] 13 6d [2] 3d 4f [2] 29 54 [2] 26 4e [2] 38 53 [2] 3a 52 [2] 21 54 [2] 3d 53 [2] 21 7c }

  condition:
    any of them
}