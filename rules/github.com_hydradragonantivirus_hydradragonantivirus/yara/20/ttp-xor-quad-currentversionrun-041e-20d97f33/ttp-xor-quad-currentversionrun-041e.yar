rule TTP_XOR_QUAD_CurrentVersionRun_041e {
  strings:
    $key_041e = { 57 71 [2] 73 7f [2] 58 53 [2] 76 71 [2] 62 6a [2] 6d 70 [2] 73 6d [2] 71 6c [2] 6a 6a [2] 76 6d [2] 6a 42 }

  condition:
    any of them
}