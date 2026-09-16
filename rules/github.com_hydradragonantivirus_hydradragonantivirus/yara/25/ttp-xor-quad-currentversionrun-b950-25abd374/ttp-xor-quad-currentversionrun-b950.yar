rule TTP_XOR_QUAD_CurrentVersionRun_b950 {
  strings:
    $key_b950 = { ea 3f [2] ce 31 [2] e5 1d [2] cb 3f [2] df 24 [2] d0 3e [2] ce 23 [2] cc 22 [2] d7 24 [2] cb 23 [2] d7 0c }

  condition:
    any of them
}