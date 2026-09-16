rule TTP_XOR_QUAD_CurrentVersionRun_917e {
  strings:
    $key_917e = { c2 11 [2] e6 1f [2] cd 33 [2] e3 11 [2] f7 0a [2] f8 10 [2] e6 0d [2] e4 0c [2] ff 0a [2] e3 0d [2] ff 22 }

  condition:
    any of them
}