rule TTP_XOR_QUAD_CurrentVersionRun_5a1e {
  strings:
    $key_5a1e = { 09 71 [2] 2d 7f [2] 06 53 [2] 28 71 [2] 3c 6a [2] 33 70 [2] 2d 6d [2] 2f 6c [2] 34 6a [2] 28 6d [2] 34 42 }

  condition:
    any of them
}