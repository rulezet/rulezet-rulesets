rule TTP_XOR_QUAD_CurrentVersionRun_b942 {
  strings:
    $key_b942 = { ea 2d [2] ce 23 [2] e5 0f [2] cb 2d [2] df 36 [2] d0 2c [2] ce 31 [2] cc 30 [2] d7 36 [2] cb 31 [2] d7 1e }

  condition:
    any of them
}