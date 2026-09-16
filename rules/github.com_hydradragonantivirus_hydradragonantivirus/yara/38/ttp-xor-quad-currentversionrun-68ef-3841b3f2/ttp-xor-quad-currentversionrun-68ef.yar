rule TTP_XOR_QUAD_CurrentVersionRun_68ef {
  strings:
    $key_68ef = { 3b 80 [2] 1f 8e [2] 34 a2 [2] 1a 80 [2] 0e 9b [2] 01 81 [2] 1f 9c [2] 1d 9d [2] 06 9b [2] 1a 9c [2] 06 b3 }

  condition:
    any of them
}