rule TTP_XOR_QUAD_CurrentVersionRun_4a3c {
  strings:
    $key_4a3c = { 19 53 [2] 3d 5d [2] 16 71 [2] 38 53 [2] 2c 48 [2] 23 52 [2] 3d 4f [2] 3f 4e [2] 24 48 [2] 38 4f [2] 24 60 }

  condition:
    any of them
}