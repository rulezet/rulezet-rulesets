rule TTP_XOR_QUAD_CurrentVersionRun_0aae {
  strings:
    $key_0aae = { 59 c1 [2] 7d cf [2] 56 e3 [2] 78 c1 [2] 6c da [2] 63 c0 [2] 7d dd [2] 7f dc [2] 64 da [2] 78 dd [2] 64 f2 }

  condition:
    any of them
}