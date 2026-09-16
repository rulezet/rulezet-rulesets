rule TTP_XOR_QUAD_CurrentVersionRun_240e {
  strings:
    $key_240e = { 77 61 [2] 53 6f [2] 78 43 [2] 56 61 [2] 42 7a [2] 4d 60 [2] 53 7d [2] 51 7c [2] 4a 7a [2] 56 7d [2] 4a 52 }

  condition:
    any of them
}