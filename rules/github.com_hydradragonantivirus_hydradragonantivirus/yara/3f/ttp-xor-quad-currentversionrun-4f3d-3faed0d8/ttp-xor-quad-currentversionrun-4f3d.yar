rule TTP_XOR_QUAD_CurrentVersionRun_4f3d {
  strings:
    $key_4f3d = { 1c 52 [2] 38 5c [2] 13 70 [2] 3d 52 [2] 29 49 [2] 26 53 [2] 38 4e [2] 3a 4f [2] 21 49 [2] 3d 4e [2] 21 61 }

  condition:
    any of them
}