rule TTP_XOR_QUAD_CurrentVersionRun_b925 {
  strings:
    $key_b925 = { ea 4a [2] ce 44 [2] e5 68 [2] cb 4a [2] df 51 [2] d0 4b [2] ce 56 [2] cc 57 [2] d7 51 [2] cb 56 [2] d7 79 }

  condition:
    any of them
}