rule TTP_XOR_QUAD_CurrentVersionRun_5fae {
  strings:
    $key_5fae = { 0c c1 [2] 28 cf [2] 03 e3 [2] 2d c1 [2] 39 da [2] 36 c0 [2] 28 dd [2] 2a dc [2] 31 da [2] 2d dd [2] 31 f2 }

  condition:
    any of them
}