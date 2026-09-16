rule TTP_XOR_QUAD_CurrentVersionRun_914b {
  strings:
    $key_914b = { c2 24 [2] e6 2a [2] cd 06 [2] e3 24 [2] f7 3f [2] f8 25 [2] e6 38 [2] e4 39 [2] ff 3f [2] e3 38 [2] ff 17 }

  condition:
    any of them
}