rule TTP_XOR_QUAD_CurrentVersionRun_6a1e {
  strings:
    $key_6a1e = { 39 71 [2] 1d 7f [2] 36 53 [2] 18 71 [2] 0c 6a [2] 03 70 [2] 1d 6d [2] 1f 6c [2] 04 6a [2] 18 6d [2] 04 42 }

  condition:
    any of them
}