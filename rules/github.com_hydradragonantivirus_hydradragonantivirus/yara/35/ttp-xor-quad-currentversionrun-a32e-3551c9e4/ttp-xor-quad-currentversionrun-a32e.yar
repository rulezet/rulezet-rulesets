rule TTP_XOR_QUAD_CurrentVersionRun_a32e {
  strings:
    $key_a32e = { f0 41 [2] d4 4f [2] ff 63 [2] d1 41 [2] c5 5a [2] ca 40 [2] d4 5d [2] d6 5c [2] cd 5a [2] d1 5d [2] cd 72 }

  condition:
    any of them
}