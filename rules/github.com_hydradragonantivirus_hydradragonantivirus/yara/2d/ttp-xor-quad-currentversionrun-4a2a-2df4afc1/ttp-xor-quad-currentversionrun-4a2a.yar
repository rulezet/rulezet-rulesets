rule TTP_XOR_QUAD_CurrentVersionRun_4a2a {
  strings:
    $key_4a2a = { 19 45 [2] 3d 4b [2] 16 67 [2] 38 45 [2] 2c 5e [2] 23 44 [2] 3d 59 [2] 3f 58 [2] 24 5e [2] 38 59 [2] 24 76 }

  condition:
    any of them
}