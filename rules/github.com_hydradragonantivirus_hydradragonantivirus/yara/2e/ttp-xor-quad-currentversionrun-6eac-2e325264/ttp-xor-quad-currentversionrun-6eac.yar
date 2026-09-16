rule TTP_XOR_QUAD_CurrentVersionRun_6eac {
  strings:
    $key_6eac = { 3d c3 [2] 19 cd [2] 32 e1 [2] 1c c3 [2] 08 d8 [2] 07 c2 [2] 19 df [2] 1b de [2] 00 d8 [2] 1c df [2] 00 f0 }

  condition:
    any of them
}