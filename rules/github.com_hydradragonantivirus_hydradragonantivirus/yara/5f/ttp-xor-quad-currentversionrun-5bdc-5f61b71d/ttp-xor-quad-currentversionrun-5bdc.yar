rule TTP_XOR_QUAD_CurrentVersionRun_5bdc {
  strings:
    $key_5bdc = { 08 b3 [2] 2c bd [2] 07 91 [2] 29 b3 [2] 3d a8 [2] 32 b2 [2] 2c af [2] 2e ae [2] 35 a8 [2] 29 af [2] 35 80 }

  condition:
    any of them
}