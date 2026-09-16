rule TTP_XOR_QUAD_CurrentVersionRun_4fae {
  strings:
    $key_4fae = { 1c c1 [2] 38 cf [2] 13 e3 [2] 3d c1 [2] 29 da [2] 26 c0 [2] 38 dd [2] 3a dc [2] 21 da [2] 3d dd [2] 21 f2 }

  condition:
    any of them
}