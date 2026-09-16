rule TTP_XOR_QUAD_CurrentVersionRun_b934 {
  strings:
    $key_b934 = { ea 5b [2] ce 55 [2] e5 79 [2] cb 5b [2] df 40 [2] d0 5a [2] ce 47 [2] cc 46 [2] d7 40 [2] cb 47 [2] d7 68 }

  condition:
    any of them
}