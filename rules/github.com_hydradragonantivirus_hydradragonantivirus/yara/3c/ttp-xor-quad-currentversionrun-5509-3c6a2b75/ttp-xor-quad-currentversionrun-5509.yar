rule TTP_XOR_QUAD_CurrentVersionRun_5509 {
  strings:
    $key_5509 = { 06 66 [2] 22 68 [2] 09 44 [2] 27 66 [2] 33 7d [2] 3c 67 [2] 22 7a [2] 20 7b [2] 3b 7d [2] 27 7a [2] 3b 55 }

  condition:
    any of them
}