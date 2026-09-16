rule TTP_XOR_QUAD_CurrentVersionRun_61ac {
  strings:
    $key_61ac = { 32 c3 [2] 16 cd [2] 3d e1 [2] 13 c3 [2] 07 d8 [2] 08 c2 [2] 16 df [2] 14 de [2] 0f d8 [2] 13 df [2] 0f f0 }

  condition:
    any of them
}