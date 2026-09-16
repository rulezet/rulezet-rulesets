rule TTP_XOR_QUAD_CurrentVersionRun_6051 {
  strings:
    $key_6051 = { 33 3e [2] 17 30 [2] 3c 1c [2] 12 3e [2] 06 25 [2] 09 3f [2] 17 22 [2] 15 23 [2] 0e 25 [2] 12 22 [2] 0e 0d }

  condition:
    any of them
}