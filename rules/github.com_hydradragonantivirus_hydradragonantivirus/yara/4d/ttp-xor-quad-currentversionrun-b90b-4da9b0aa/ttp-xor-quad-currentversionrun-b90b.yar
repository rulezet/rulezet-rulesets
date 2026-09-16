rule TTP_XOR_QUAD_CurrentVersionRun_b90b {
  strings:
    $key_b90b = { ea 64 [2] ce 6a [2] e5 46 [2] cb 64 [2] df 7f [2] d0 65 [2] ce 78 [2] cc 79 [2] d7 7f [2] cb 78 [2] d7 57 }

  condition:
    any of them
}