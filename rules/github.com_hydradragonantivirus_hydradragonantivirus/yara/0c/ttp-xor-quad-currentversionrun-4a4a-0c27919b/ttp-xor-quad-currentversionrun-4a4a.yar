rule TTP_XOR_QUAD_CurrentVersionRun_4a4a {
  strings:
    $key_4a4a = { 19 25 [2] 3d 2b [2] 16 07 [2] 38 25 [2] 2c 3e [2] 23 24 [2] 3d 39 [2] 3f 38 [2] 24 3e [2] 38 39 [2] 24 16 }

  condition:
    any of them
}