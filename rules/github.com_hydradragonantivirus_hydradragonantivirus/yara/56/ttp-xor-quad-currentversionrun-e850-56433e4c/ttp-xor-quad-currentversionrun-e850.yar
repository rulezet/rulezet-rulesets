rule TTP_XOR_QUAD_CurrentVersionRun_e850 {
  strings:
    $key_e850 = { bb 3f [2] 9f 31 [2] b4 1d [2] 9a 3f [2] 8e 24 [2] 81 3e [2] 9f 23 [2] 9d 22 [2] 86 24 [2] 9a 23 [2] 86 0c }

  condition:
    any of them
}