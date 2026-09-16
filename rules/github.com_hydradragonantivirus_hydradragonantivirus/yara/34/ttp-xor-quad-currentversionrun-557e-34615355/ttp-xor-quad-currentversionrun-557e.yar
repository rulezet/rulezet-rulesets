rule TTP_XOR_QUAD_CurrentVersionRun_557e {
  strings:
    $key_557e = { 06 11 [2] 22 1f [2] 09 33 [2] 27 11 [2] 33 0a [2] 3c 10 [2] 22 0d [2] 20 0c [2] 3b 0a [2] 27 0d [2] 3b 22 }

  condition:
    any of them
}