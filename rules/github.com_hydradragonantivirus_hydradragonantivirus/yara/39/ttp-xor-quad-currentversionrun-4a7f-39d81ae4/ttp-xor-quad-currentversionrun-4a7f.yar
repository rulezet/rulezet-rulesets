rule TTP_XOR_QUAD_CurrentVersionRun_4a7f {
  strings:
    $key_4a7f = { 19 10 [2] 3d 1e [2] 16 32 [2] 38 10 [2] 2c 0b [2] 23 11 [2] 3d 0c [2] 3f 0d [2] 24 0b [2] 38 0c [2] 24 23 }

  condition:
    any of them
}