rule TTP_XOR_QUAD_CurrentVersionRun_b951 {
  strings:
    $key_b951 = { ea 3e [2] ce 30 [2] e5 1c [2] cb 3e [2] df 25 [2] d0 3f [2] ce 22 [2] cc 23 [2] d7 25 [2] cb 22 [2] d7 0d }

  condition:
    any of them
}