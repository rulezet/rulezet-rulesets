rule TTP_XOR_QUAD_CurrentVersionRun_e2ae {
  strings:
    $key_e2ae = { b1 c1 [2] 95 cf [2] be e3 [2] 90 c1 [2] 84 da [2] 8b c0 [2] 95 dd [2] 97 dc [2] 8c da [2] 90 dd [2] 8c f2 }

  condition:
    any of them
}