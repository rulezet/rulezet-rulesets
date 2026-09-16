rule TTP_XOR_QUAD_CurrentVersionRun_6748 {
  strings:
    $key_6748 = { 34 27 [2] 10 29 [2] 3b 05 [2] 15 27 [2] 01 3c [2] 0e 26 [2] 10 3b [2] 12 3a [2] 09 3c [2] 15 3b [2] 09 14 }

  condition:
    any of them
}