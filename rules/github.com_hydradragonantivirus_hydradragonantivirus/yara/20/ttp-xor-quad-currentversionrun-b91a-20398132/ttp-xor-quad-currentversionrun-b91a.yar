rule TTP_XOR_QUAD_CurrentVersionRun_b91a {
  strings:
    $key_b91a = { ea 75 [2] ce 7b [2] e5 57 [2] cb 75 [2] df 6e [2] d0 74 [2] ce 69 [2] cc 68 [2] d7 6e [2] cb 69 [2] d7 46 }

  condition:
    any of them
}