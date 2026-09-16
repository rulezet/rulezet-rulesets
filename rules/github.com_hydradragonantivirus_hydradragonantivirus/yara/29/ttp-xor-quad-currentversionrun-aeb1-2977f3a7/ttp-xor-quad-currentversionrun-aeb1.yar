rule TTP_XOR_QUAD_CurrentVersionRun_aeb1 {
  strings:
    $key_aeb1 = { fd de [2] d9 d0 [2] f2 fc [2] dc de [2] c8 c5 [2] c7 df [2] d9 c2 [2] db c3 [2] c0 c5 [2] dc c2 [2] c0 ed }

  condition:
    any of them
}