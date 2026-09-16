rule TTP_XOR_QUAD_CurrentVersionRun_b92a {
  strings:
    $key_b92a = { ea 45 [2] ce 4b [2] e5 67 [2] cb 45 [2] df 5e [2] d0 44 [2] ce 59 [2] cc 58 [2] d7 5e [2] cb 59 [2] d7 76 }

  condition:
    any of them
}