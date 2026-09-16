rule TTP_XOR_QUAD_CurrentVersionRun_b93b {
  strings:
    $key_b93b = { ea 54 [2] ce 5a [2] e5 76 [2] cb 54 [2] df 4f [2] d0 55 [2] ce 48 [2] cc 49 [2] d7 4f [2] cb 48 [2] d7 67 }

  condition:
    any of them
}