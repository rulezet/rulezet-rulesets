rule TTP_XOR_QUAD_CurrentVersionRun_b987 {
  strings:
    $key_b987 = { ea e8 [2] ce e6 [2] e5 ca [2] cb e8 [2] df f3 [2] d0 e9 [2] ce f4 [2] cc f5 [2] d7 f3 [2] cb f4 [2] d7 db }

  condition:
    any of them
}