rule TTP_XOR_QUAD_CurrentVersionRun_684a {
  strings:
    $key_684a = { 3b 25 [2] 1f 2b [2] 34 07 [2] 1a 25 [2] 0e 3e [2] 01 24 [2] 1f 39 [2] 1d 38 [2] 06 3e [2] 1a 39 [2] 06 16 }

  condition:
    any of them
}