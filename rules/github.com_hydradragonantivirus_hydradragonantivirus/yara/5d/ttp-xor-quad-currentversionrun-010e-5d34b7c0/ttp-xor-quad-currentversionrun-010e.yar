rule TTP_XOR_QUAD_CurrentVersionRun_010e {
  strings:
    $key_010e = { 52 61 [2] 76 6f [2] 5d 43 [2] 73 61 [2] 67 7a [2] 68 60 [2] 76 7d [2] 74 7c [2] 6f 7a [2] 73 7d [2] 6f 52 }

  condition:
    any of them
}