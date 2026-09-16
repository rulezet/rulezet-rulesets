rule TTP_XOR_QUAD_CurrentVersionRun_b9b2 {
  strings:
    $key_b9b2 = { ea dd [2] ce d3 [2] e5 ff [2] cb dd [2] df c6 [2] d0 dc [2] ce c1 [2] cc c0 [2] d7 c6 [2] cb c1 [2] d7 ee }

  condition:
    any of them
}