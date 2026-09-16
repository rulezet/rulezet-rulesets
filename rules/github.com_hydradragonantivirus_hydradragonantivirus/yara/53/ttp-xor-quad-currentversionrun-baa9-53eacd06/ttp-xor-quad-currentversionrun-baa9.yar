rule TTP_XOR_QUAD_CurrentVersionRun_baa9 {
  strings:
    $key_baa9 = { e9 c6 [2] cd c8 [2] e6 e4 [2] c8 c6 [2] dc dd [2] d3 c7 [2] cd da [2] cf db [2] d4 dd [2] c8 da [2] d4 f5 }

  condition:
    any of them
}