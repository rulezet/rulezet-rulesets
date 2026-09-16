rule TTP_XOR_QUAD_CurrentVersionRun_aeae {
  strings:
    $key_aeae = { fd c1 [2] d9 cf [2] f2 e3 [2] dc c1 [2] c8 da [2] c7 c0 [2] d9 dd [2] db dc [2] c0 da [2] dc dd [2] c0 f2 }

  condition:
    any of them
}