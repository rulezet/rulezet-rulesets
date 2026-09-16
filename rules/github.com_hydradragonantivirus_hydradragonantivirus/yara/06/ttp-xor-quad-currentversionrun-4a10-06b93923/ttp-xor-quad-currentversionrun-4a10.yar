rule TTP_XOR_QUAD_CurrentVersionRun_4a10 {
  strings:
    $key_4a10 = { 19 7f [2] 3d 71 [2] 16 5d [2] 38 7f [2] 2c 64 [2] 23 7e [2] 3d 63 [2] 3f 62 [2] 24 64 [2] 38 63 [2] 24 4c }

  condition:
    any of them
}