rule TTP_XOR_QUAD_CurrentVersionRun_4a0a {
  strings:
    $key_4a0a = { 19 65 [2] 3d 6b [2] 16 47 [2] 38 65 [2] 2c 7e [2] 23 64 [2] 3d 79 [2] 3f 78 [2] 24 7e [2] 38 79 [2] 24 56 }

  condition:
    any of them
}