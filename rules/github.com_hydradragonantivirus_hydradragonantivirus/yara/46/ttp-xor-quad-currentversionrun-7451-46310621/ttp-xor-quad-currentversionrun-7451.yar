rule TTP_XOR_QUAD_CurrentVersionRun_7451 {
  strings:
    $key_7451 = { 27 3e [2] 03 30 [2] 28 1c [2] 06 3e [2] 12 25 [2] 1d 3f [2] 03 22 [2] 01 23 [2] 1a 25 [2] 06 22 [2] 1a 0d }

  condition:
    any of them
}