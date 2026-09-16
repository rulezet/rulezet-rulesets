rule TTP_XOR_QUAD_CurrentVersionRun_5bbe {
  strings:
    $key_5bbe = { 08 d1 [2] 2c df [2] 07 f3 [2] 29 d1 [2] 3d ca [2] 32 d0 [2] 2c cd [2] 2e cc [2] 35 ca [2] 29 cd [2] 35 e2 }

  condition:
    any of them
}