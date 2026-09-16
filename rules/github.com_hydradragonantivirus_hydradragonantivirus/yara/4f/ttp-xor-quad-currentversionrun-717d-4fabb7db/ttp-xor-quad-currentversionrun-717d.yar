rule TTP_XOR_QUAD_CurrentVersionRun_717d {
  strings:
    $key_717d = { 22 12 [2] 06 1c [2] 2d 30 [2] 03 12 [2] 17 09 [2] 18 13 [2] 06 0e [2] 04 0f [2] 1f 09 [2] 03 0e [2] 1f 21 }

  condition:
    any of them
}