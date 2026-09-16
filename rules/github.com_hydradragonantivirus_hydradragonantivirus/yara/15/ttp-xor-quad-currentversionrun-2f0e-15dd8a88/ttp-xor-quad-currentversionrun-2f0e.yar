rule TTP_XOR_QUAD_CurrentVersionRun_2f0e {
  strings:
    $key_2f0e = { 7c 61 [2] 58 6f [2] 73 43 [2] 5d 61 [2] 49 7a [2] 46 60 [2] 58 7d [2] 5a 7c [2] 41 7a [2] 5d 7d [2] 41 52 }

  condition:
    any of them
}