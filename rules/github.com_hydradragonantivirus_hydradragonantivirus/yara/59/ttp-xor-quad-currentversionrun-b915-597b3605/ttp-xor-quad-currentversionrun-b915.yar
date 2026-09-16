rule TTP_XOR_QUAD_CurrentVersionRun_b915 {
  strings:
    $key_b915 = { ea 7a [2] ce 74 [2] e5 58 [2] cb 7a [2] df 61 [2] d0 7b [2] ce 66 [2] cc 67 [2] d7 61 [2] cb 66 [2] d7 49 }

  condition:
    any of them
}