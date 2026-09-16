rule TTP_XOR_QUAD_CurrentVersionRun_a31e {
  strings:
    $key_a31e = { f0 71 [2] d4 7f [2] ff 53 [2] d1 71 [2] c5 6a [2] ca 70 [2] d4 6d [2] d6 6c [2] cd 6a [2] d1 6d [2] cd 42 }

  condition:
    any of them
}