rule TTP_XOR_QUAD_CurrentVersionRun_b92e {
  strings:
    $key_b92e = { ea 41 [2] ce 4f [2] e5 63 [2] cb 41 [2] df 5a [2] d0 40 [2] ce 5d [2] cc 5c [2] d7 5a [2] cb 5d [2] d7 72 }

  condition:
    any of them
}