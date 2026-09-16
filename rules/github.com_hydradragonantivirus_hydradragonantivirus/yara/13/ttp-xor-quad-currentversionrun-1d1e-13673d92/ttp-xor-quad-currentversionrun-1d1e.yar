rule TTP_XOR_QUAD_CurrentVersionRun_1d1e {
  strings:
    $key_1d1e = { 4e 71 [2] 6a 7f [2] 41 53 [2] 6f 71 [2] 7b 6a [2] 74 70 [2] 6a 6d [2] 68 6c [2] 73 6a [2] 6f 6d [2] 73 42 }

  condition:
    any of them
}