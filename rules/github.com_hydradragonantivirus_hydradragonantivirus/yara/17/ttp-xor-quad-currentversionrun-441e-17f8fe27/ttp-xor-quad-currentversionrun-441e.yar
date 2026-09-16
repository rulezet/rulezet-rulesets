rule TTP_XOR_QUAD_CurrentVersionRun_441e {
  strings:
    $key_441e = { 17 71 [2] 33 7f [2] 18 53 [2] 36 71 [2] 22 6a [2] 2d 70 [2] 33 6d [2] 31 6c [2] 2a 6a [2] 36 6d [2] 2a 42 }

  condition:
    any of them
}