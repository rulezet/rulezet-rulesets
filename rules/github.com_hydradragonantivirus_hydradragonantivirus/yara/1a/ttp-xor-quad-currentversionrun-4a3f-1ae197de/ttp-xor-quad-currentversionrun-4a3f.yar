rule TTP_XOR_QUAD_CurrentVersionRun_4a3f {
  strings:
    $key_4a3f = { 19 50 [2] 3d 5e [2] 16 72 [2] 38 50 [2] 2c 4b [2] 23 51 [2] 3d 4c [2] 3f 4d [2] 24 4b [2] 38 4c [2] 24 63 }

  condition:
    any of them
}