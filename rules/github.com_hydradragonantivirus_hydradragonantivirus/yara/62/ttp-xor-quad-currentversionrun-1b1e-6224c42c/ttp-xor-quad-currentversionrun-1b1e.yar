rule TTP_XOR_QUAD_CurrentVersionRun_1b1e {
  strings:
    $key_1b1e = { 48 71 [2] 6c 7f [2] 47 53 [2] 69 71 [2] 7d 6a [2] 72 70 [2] 6c 6d [2] 6e 6c [2] 75 6a [2] 69 6d [2] 75 42 }

  condition:
    any of them
}