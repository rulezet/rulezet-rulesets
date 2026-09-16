rule TTP_XOR_QUAD_CurrentVersionRun_b94a {
  strings:
    $key_b94a = { ea 25 [2] ce 2b [2] e5 07 [2] cb 25 [2] df 3e [2] d0 24 [2] ce 39 [2] cc 38 [2] d7 3e [2] cb 39 [2] d7 16 }

  condition:
    any of them
}