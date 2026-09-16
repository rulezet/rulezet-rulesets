rule TTP_XOR_QUAD_CurrentVersionRun_b926 {
  strings:
    $key_b926 = { ea 49 [2] ce 47 [2] e5 6b [2] cb 49 [2] df 52 [2] d0 48 [2] ce 55 [2] cc 54 [2] d7 52 [2] cb 55 [2] d7 7a }

  condition:
    any of them
}