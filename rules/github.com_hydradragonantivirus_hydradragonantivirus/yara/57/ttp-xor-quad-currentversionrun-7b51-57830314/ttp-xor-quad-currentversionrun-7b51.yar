rule TTP_XOR_QUAD_CurrentVersionRun_7b51 {
  strings:
    $key_7b51 = { 28 3e [2] 0c 30 [2] 27 1c [2] 09 3e [2] 1d 25 [2] 12 3f [2] 0c 22 [2] 0e 23 [2] 15 25 [2] 09 22 [2] 15 0d }

  condition:
    any of them
}