rule TTP_XOR_QUAD_CurrentVersionRun_b9d8 {
  strings:
    $key_b9d8 = { ea b7 [2] ce b9 [2] e5 95 [2] cb b7 [2] df ac [2] d0 b6 [2] ce ab [2] cc aa [2] d7 ac [2] cb ab [2] d7 84 }

  condition:
    any of them
}