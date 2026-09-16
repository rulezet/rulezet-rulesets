rule TTP_XOR_QUAD_CurrentVersionRun_5b3c {
  strings:
    $key_5b3c = { 08 53 [2] 2c 5d [2] 07 71 [2] 29 53 [2] 3d 48 [2] 32 52 [2] 2c 4f [2] 2e 4e [2] 35 48 [2] 29 4f [2] 35 60 }

  condition:
    any of them
}