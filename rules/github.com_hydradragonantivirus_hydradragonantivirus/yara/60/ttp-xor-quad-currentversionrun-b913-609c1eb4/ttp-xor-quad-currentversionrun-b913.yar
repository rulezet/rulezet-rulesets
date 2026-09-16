rule TTP_XOR_QUAD_CurrentVersionRun_b913 {
  strings:
    $key_b913 = { ea 7c [2] ce 72 [2] e5 5e [2] cb 7c [2] df 67 [2] d0 7d [2] ce 60 [2] cc 61 [2] d7 67 [2] cb 60 [2] d7 4f }

  condition:
    any of them
}