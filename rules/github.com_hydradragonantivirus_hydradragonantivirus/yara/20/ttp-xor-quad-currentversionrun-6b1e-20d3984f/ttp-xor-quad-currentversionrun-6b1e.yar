rule TTP_XOR_QUAD_CurrentVersionRun_6b1e {
  strings:
    $key_6b1e = { 38 71 [2] 1c 7f [2] 37 53 [2] 19 71 [2] 0d 6a [2] 02 70 [2] 1c 6d [2] 1e 6c [2] 05 6a [2] 19 6d [2] 05 42 }

  condition:
    any of them
}