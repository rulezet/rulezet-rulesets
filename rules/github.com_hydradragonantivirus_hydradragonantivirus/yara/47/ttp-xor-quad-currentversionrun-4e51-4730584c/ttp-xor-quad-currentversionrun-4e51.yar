rule TTP_XOR_QUAD_CurrentVersionRun_4e51 {
  strings:
    $key_4e51 = { 1d 3e [2] 39 30 [2] 12 1c [2] 3c 3e [2] 28 25 [2] 27 3f [2] 39 22 [2] 3b 23 [2] 20 25 [2] 3c 22 [2] 20 0d }

  condition:
    any of them
}