rule TTP_XOR_QUAD_CurrentVersionRun_ba8f {
  strings:
    $key_ba8f = { e9 e0 [2] cd ee [2] e6 c2 [2] c8 e0 [2] dc fb [2] d3 e1 [2] cd fc [2] cf fd [2] d4 fb [2] c8 fc [2] d4 d3 }

  condition:
    any of them
}