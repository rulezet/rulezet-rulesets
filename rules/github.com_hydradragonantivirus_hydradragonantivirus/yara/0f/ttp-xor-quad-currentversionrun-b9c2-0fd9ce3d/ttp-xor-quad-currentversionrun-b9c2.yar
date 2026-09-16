rule TTP_XOR_QUAD_CurrentVersionRun_b9c2 {
  strings:
    $key_b9c2 = { ea ad [2] ce a3 [2] e5 8f [2] cb ad [2] df b6 [2] d0 ac [2] ce b1 [2] cc b0 [2] d7 b6 [2] cb b1 [2] d7 9e }

  condition:
    any of them
}