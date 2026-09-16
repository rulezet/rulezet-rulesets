rule TTP_XOR_QUAD_CurrentVersionRun_b96a {
  strings:
    $key_b96a = { ea 05 [2] ce 0b [2] e5 27 [2] cb 05 [2] df 1e [2] d0 04 [2] ce 19 [2] cc 18 [2] d7 1e [2] cb 19 [2] d7 36 }

  condition:
    any of them
}