rule TTP_XOR_QUAD_CurrentVersionRun_4a1c {
  strings:
    $key_4a1c = { 19 73 [2] 3d 7d [2] 16 51 [2] 38 73 [2] 2c 68 [2] 23 72 [2] 3d 6f [2] 3f 6e [2] 24 68 [2] 38 6f [2] 24 40 }

  condition:
    any of them
}