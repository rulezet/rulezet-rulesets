rule TTP_XOR_QUAD_CurrentVersionRun_b97e {
  strings:
    $key_b97e = { ea 11 [2] ce 1f [2] e5 33 [2] cb 11 [2] df 0a [2] d0 10 [2] ce 0d [2] cc 0c [2] d7 0a [2] cb 0d [2] d7 22 }

  condition:
    any of them
}