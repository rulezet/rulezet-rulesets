rule TTP_XOR_QUAD_CurrentVersionRun_040e {
  strings:
    $key_040e = { 57 61 [2] 73 6f [2] 58 43 [2] 76 61 [2] 62 7a [2] 6d 60 [2] 73 7d [2] 71 7c [2] 6a 7a [2] 76 7d [2] 6a 52 }

  condition:
    any of them
}