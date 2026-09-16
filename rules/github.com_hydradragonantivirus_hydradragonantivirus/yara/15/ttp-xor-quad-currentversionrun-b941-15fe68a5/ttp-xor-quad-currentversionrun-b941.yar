rule TTP_XOR_QUAD_CurrentVersionRun_b941 {
  strings:
    $key_b941 = { ea 2e [2] ce 20 [2] e5 0c [2] cb 2e [2] df 35 [2] d0 2f [2] ce 32 [2] cc 33 [2] d7 35 [2] cb 32 [2] d7 1d }

  condition:
    any of them
}