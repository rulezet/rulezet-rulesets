rule TTP_XOR_QUAD_CurrentVersionRun_62ae {
  strings:
    $key_62ae = { 31 c1 [2] 15 cf [2] 3e e3 [2] 10 c1 [2] 04 da [2] 0b c0 [2] 15 dd [2] 17 dc [2] 0c da [2] 10 dd [2] 0c f2 }

  condition:
    any of them
}