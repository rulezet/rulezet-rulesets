rule TTP_XOR_QUAD_CurrentVersionRun_bfb1 {
  strings:
    $key_bfb1 = { ec de [2] c8 d0 [2] e3 fc [2] cd de [2] d9 c5 [2] d6 df [2] c8 c2 [2] ca c3 [2] d1 c5 [2] cd c2 [2] d1 ed }

  condition:
    any of them
}