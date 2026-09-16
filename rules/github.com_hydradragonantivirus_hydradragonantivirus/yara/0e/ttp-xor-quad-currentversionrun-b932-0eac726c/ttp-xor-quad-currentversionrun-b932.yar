rule TTP_XOR_QUAD_CurrentVersionRun_b932 {
  strings:
    $key_b932 = { ea 5d [2] ce 53 [2] e5 7f [2] cb 5d [2] df 46 [2] d0 5c [2] ce 41 [2] cc 40 [2] d7 46 [2] cb 41 [2] d7 6e }

  condition:
    any of them
}