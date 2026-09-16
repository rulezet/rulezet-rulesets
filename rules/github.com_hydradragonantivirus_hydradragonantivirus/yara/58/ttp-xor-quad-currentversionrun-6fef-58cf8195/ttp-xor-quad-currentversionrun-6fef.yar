rule TTP_XOR_QUAD_CurrentVersionRun_6fef {
  strings:
    $key_6fef = { 3c 80 [2] 18 8e [2] 33 a2 [2] 1d 80 [2] 09 9b [2] 06 81 [2] 18 9c [2] 1a 9d [2] 01 9b [2] 1d 9c [2] 01 b3 }

  condition:
    any of them
}