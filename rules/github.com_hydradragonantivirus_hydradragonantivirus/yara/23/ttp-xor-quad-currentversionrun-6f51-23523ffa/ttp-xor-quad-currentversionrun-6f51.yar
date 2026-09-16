rule TTP_XOR_QUAD_CurrentVersionRun_6f51 {
  strings:
    $key_6f51 = { 3c 3e [2] 18 30 [2] 33 1c [2] 1d 3e [2] 09 25 [2] 06 3f [2] 18 22 [2] 1a 23 [2] 01 25 [2] 1d 22 [2] 01 0d }

  condition:
    any of them
}