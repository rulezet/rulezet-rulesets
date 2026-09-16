rule TTP_XOR_QUAD_CurrentVersionRun_b9ec {
  strings:
    $key_b9ec = { ea 83 [2] ce 8d [2] e5 a1 [2] cb 83 [2] df 98 [2] d0 82 [2] ce 9f [2] cc 9e [2] d7 98 [2] cb 9f [2] d7 b0 }

  condition:
    any of them
}