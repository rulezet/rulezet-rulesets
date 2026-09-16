rule TTP_XOR_QUAD_CurrentVersionRun_141e {
  strings:
    $key_141e = { 47 71 [2] 63 7f [2] 48 53 [2] 66 71 [2] 72 6a [2] 7d 70 [2] 63 6d [2] 61 6c [2] 7a 6a [2] 66 6d [2] 7a 42 }

  condition:
    any of them
}