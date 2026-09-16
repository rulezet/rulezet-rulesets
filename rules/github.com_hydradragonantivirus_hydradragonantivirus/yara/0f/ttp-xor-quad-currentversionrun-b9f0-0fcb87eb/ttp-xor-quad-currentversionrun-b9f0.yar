rule TTP_XOR_QUAD_CurrentVersionRun_b9f0 {
  strings:
    $key_b9f0 = { ea 9f [2] ce 91 [2] e5 bd [2] cb 9f [2] df 84 [2] d0 9e [2] ce 83 [2] cc 82 [2] d7 84 [2] cb 83 [2] d7 ac }

  condition:
    any of them
}