rule TTP_XOR_QUAD_CurrentVersionRun_4afa {
  strings:
    $key_4afa = { 19 95 [2] 3d 9b [2] 16 b7 [2] 38 95 [2] 2c 8e [2] 23 94 [2] 3d 89 [2] 3f 88 [2] 24 8e [2] 38 89 [2] 24 a6 }

  condition:
    any of them
}