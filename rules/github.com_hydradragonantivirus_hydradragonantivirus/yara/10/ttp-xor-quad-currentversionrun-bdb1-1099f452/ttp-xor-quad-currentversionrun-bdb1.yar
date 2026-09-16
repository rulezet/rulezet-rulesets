rule TTP_XOR_QUAD_CurrentVersionRun_bdb1 {
  strings:
    $key_bdb1 = { ee de [2] ca d0 [2] e1 fc [2] cf de [2] db c5 [2] d4 df [2] ca c2 [2] c8 c3 [2] d3 c5 [2] cf c2 [2] d3 ed }

  condition:
    any of them
}