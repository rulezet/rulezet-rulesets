rule TTP_XOR_QUAD_CurrentVersionRun_b9c8 {
  strings:
    $key_b9c8 = { ea a7 [2] ce a9 [2] e5 85 [2] cb a7 [2] df bc [2] d0 a6 [2] ce bb [2] cc ba [2] d7 bc [2] cb bb [2] d7 94 }

  condition:
    any of them
}