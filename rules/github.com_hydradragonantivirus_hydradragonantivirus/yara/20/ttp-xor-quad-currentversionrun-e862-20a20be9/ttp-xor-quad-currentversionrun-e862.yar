rule TTP_XOR_QUAD_CurrentVersionRun_e862 {
  strings:
    $key_e862 = { bb 0d [2] 9f 03 [2] b4 2f [2] 9a 0d [2] 8e 16 [2] 81 0c [2] 9f 11 [2] 9d 10 [2] 86 16 [2] 9a 11 [2] 86 3e }

  condition:
    any of them
}