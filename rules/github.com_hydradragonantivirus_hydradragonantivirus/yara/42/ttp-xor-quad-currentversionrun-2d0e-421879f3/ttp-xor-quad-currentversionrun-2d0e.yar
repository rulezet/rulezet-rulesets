rule TTP_XOR_QUAD_CurrentVersionRun_2d0e {
  strings:
    $key_2d0e = { 7e 61 [2] 5a 6f [2] 71 43 [2] 5f 61 [2] 4b 7a [2] 44 60 [2] 5a 7d [2] 58 7c [2] 43 7a [2] 5f 7d [2] 43 52 }

  condition:
    any of them
}