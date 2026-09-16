rule TTP_XOR_QUAD_CurrentVersionRun_aeb3 {
  strings:
    $key_aeb3 = { fd dc [2] d9 d2 [2] f2 fe [2] dc dc [2] c8 c7 [2] c7 dd [2] d9 c0 [2] db c1 [2] c0 c7 [2] dc c0 [2] c0 ef }

  condition:
    any of them
}