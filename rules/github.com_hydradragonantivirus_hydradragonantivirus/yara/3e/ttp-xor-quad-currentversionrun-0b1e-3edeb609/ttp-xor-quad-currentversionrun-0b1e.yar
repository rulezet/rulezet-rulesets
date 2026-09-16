rule TTP_XOR_QUAD_CurrentVersionRun_0b1e {
  strings:
    $key_0b1e = { 58 71 [2] 7c 7f [2] 57 53 [2] 79 71 [2] 6d 6a [2] 62 70 [2] 7c 6d [2] 7e 6c [2] 65 6a [2] 79 6d [2] 65 42 }

  condition:
    any of them
}