rule TTP_XOR_QUAD_CurrentVersionRun_2d1e {
  strings:
    $key_2d1e = { 7e 71 [2] 5a 7f [2] 71 53 [2] 5f 71 [2] 4b 6a [2] 44 70 [2] 5a 6d [2] 58 6c [2] 43 6a [2] 5f 6d [2] 43 42 }

  condition:
    any of them
}