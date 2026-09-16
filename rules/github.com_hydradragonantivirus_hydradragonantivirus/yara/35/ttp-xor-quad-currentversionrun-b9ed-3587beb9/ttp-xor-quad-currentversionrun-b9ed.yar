rule TTP_XOR_QUAD_CurrentVersionRun_b9ed {
  strings:
    $key_b9ed = { ea 82 [2] ce 8c [2] e5 a0 [2] cb 82 [2] df 99 [2] d0 83 [2] ce 9e [2] cc 9f [2] d7 99 [2] cb 9e [2] d7 b1 }

  condition:
    any of them
}