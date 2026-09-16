rule TTP_XOR_QUAD_CurrentVersionRun_bf8f {
  strings:
    $key_bf8f = { ec e0 [2] c8 ee [2] e3 c2 [2] cd e0 [2] d9 fb [2] d6 e1 [2] c8 fc [2] ca fd [2] d1 fb [2] cd fc [2] d1 d3 }

  condition:
    any of them
}