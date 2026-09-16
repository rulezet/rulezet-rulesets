rule TTP_XOR_QUAD_CurrentVersionRun_e841 {
  strings:
    $key_e841 = { bb 2e [2] 9f 20 [2] b4 0c [2] 9a 2e [2] 8e 35 [2] 81 2f [2] 9f 32 [2] 9d 33 [2] 86 35 [2] 9a 32 [2] 86 1d }

  condition:
    any of them
}