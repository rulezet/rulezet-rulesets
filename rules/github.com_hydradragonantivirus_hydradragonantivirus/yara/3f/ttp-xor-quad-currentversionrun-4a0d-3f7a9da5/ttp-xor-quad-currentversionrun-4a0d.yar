rule TTP_XOR_QUAD_CurrentVersionRun_4a0d {
  strings:
    $key_4a0d = { 19 62 [2] 3d 6c [2] 16 40 [2] 38 62 [2] 2c 79 [2] 23 63 [2] 3d 7e [2] 3f 7f [2] 24 79 [2] 38 7e [2] 24 51 }

  condition:
    any of them
}