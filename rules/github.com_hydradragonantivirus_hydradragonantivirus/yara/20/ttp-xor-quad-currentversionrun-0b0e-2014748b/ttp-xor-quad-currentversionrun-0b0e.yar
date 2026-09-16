rule TTP_XOR_QUAD_CurrentVersionRun_0b0e {
  strings:
    $key_0b0e = { 58 61 [2] 7c 6f [2] 57 43 [2] 79 61 [2] 6d 7a [2] 62 60 [2] 7c 7d [2] 7e 7c [2] 65 7a [2] 79 7d [2] 65 52 }

  condition:
    any of them
}