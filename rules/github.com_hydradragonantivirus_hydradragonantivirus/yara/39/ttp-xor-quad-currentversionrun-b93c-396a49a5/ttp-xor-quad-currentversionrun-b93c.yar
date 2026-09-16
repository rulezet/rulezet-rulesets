rule TTP_XOR_QUAD_CurrentVersionRun_b93c {
  strings:
    $key_b93c = { ea 53 [2] ce 5d [2] e5 71 [2] cb 53 [2] df 48 [2] d0 52 [2] ce 4f [2] cc 4e [2] d7 48 [2] cb 4f [2] d7 60 }

  condition:
    any of them
}