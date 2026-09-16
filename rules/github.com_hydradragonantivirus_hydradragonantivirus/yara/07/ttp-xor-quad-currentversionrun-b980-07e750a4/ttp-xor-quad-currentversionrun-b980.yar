rule TTP_XOR_QUAD_CurrentVersionRun_b980 {
  strings:
    $key_b980 = { ea ef [2] ce e1 [2] e5 cd [2] cb ef [2] df f4 [2] d0 ee [2] ce f3 [2] cc f2 [2] d7 f4 [2] cb f3 [2] d7 dc }

  condition:
    any of them
}