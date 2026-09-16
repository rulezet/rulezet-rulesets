rule TTP_XOR_QUAD_CurrentVersionRun_cba0 {
  strings:
    $key_cba0 = { 98 cf [2] bc c1 [2] 97 ed [2] b9 cf [2] ad d4 [2] a2 ce [2] bc d3 [2] be d2 [2] a5 d4 [2] b9 d3 [2] a5 fc }

  condition:
    any of them
}