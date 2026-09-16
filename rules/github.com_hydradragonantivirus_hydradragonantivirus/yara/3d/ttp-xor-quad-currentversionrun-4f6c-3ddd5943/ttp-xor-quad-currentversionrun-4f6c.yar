rule TTP_XOR_QUAD_CurrentVersionRun_4f6c {
  strings:
    $key_4f6c = { 1c 03 [2] 38 0d [2] 13 21 [2] 3d 03 [2] 29 18 [2] 26 02 [2] 38 1f [2] 3a 1e [2] 21 18 [2] 3d 1f [2] 21 30 }

  condition:
    any of them
}