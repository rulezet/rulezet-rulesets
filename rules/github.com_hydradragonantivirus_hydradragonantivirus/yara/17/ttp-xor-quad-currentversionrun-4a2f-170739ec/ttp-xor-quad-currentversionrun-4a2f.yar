rule TTP_XOR_QUAD_CurrentVersionRun_4a2f {
  strings:
    $key_4a2f = { 19 40 [2] 3d 4e [2] 16 62 [2] 38 40 [2] 2c 5b [2] 23 41 [2] 3d 5c [2] 3f 5d [2] 24 5b [2] 38 5c [2] 24 73 }

  condition:
    any of them
}