rule TTP_XOR_QUAD_CurrentVersionRun_e851 {
  strings:
    $key_e851 = { bb 3e [2] 9f 30 [2] b4 1c [2] 9a 3e [2] 8e 25 [2] 81 3f [2] 9f 22 [2] 9d 23 [2] 86 25 [2] 9a 22 [2] 86 0d }

  condition:
    any of them
}