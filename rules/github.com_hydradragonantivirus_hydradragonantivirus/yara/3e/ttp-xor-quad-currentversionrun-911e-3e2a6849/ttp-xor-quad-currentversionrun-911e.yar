rule TTP_XOR_QUAD_CurrentVersionRun_911e {
  strings:
    $key_911e = { c2 71 [2] e6 7f [2] cd 53 [2] e3 71 [2] f7 6a [2] f8 70 [2] e6 6d [2] e4 6c [2] ff 6a [2] e3 6d [2] ff 42 }

  condition:
    any of them
}