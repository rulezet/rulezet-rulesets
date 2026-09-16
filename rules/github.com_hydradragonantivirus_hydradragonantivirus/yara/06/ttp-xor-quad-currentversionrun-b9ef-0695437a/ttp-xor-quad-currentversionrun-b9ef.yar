rule TTP_XOR_QUAD_CurrentVersionRun_b9ef {
  strings:
    $key_b9ef = { ea 80 [2] ce 8e [2] e5 a2 [2] cb 80 [2] df 9b [2] d0 81 [2] ce 9c [2] cc 9d [2] d7 9b [2] cb 9c [2] d7 b3 }

  condition:
    any of them
}