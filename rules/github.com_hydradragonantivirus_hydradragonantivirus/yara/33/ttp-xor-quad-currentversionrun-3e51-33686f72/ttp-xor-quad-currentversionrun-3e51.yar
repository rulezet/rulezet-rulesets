rule TTP_XOR_QUAD_CurrentVersionRun_3e51 {
  strings:
    $key_3e51 = { 6d 3e [2] 49 30 [2] 62 1c [2] 4c 3e [2] 58 25 [2] 57 3f [2] 49 22 [2] 4b 23 [2] 50 25 [2] 4c 22 [2] 50 0d }

  condition:
    any of them
}