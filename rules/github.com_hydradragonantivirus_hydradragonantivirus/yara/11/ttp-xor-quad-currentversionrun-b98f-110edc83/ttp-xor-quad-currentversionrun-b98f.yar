rule TTP_XOR_QUAD_CurrentVersionRun_b98f {
  strings:
    $key_b98f = { ea e0 [2] ce ee [2] e5 c2 [2] cb e0 [2] df fb [2] d0 e1 [2] ce fc [2] cc fd [2] d7 fb [2] cb fc [2] d7 d3 }

  condition:
    any of them
}