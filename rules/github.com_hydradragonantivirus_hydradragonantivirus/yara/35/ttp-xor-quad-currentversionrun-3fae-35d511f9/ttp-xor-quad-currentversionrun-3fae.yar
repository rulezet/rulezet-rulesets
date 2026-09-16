rule TTP_XOR_QUAD_CurrentVersionRun_3fae {
  strings:
    $key_3fae = { 6c c1 [2] 48 cf [2] 63 e3 [2] 4d c1 [2] 59 da [2] 56 c0 [2] 48 dd [2] 4a dc [2] 51 da [2] 4d dd [2] 51 f2 }

  condition:
    any of them
}