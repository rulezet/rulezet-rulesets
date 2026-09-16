rule TTP_XOR_QUAD_CurrentVersionRun_7fae {
  strings:
    $key_7fae = { 2c c1 [2] 08 cf [2] 23 e3 [2] 0d c1 [2] 19 da [2] 16 c0 [2] 08 dd [2] 0a dc [2] 11 da [2] 0d dd [2] 11 f2 }

  condition:
    any of them
}