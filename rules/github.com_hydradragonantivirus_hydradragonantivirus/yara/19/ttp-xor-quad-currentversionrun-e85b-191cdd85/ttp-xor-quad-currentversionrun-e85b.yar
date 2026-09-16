rule TTP_XOR_QUAD_CurrentVersionRun_e85b {
  strings:
    $key_e85b = { bb 34 [2] 9f 3a [2] b4 16 [2] 9a 34 [2] 8e 2f [2] 81 35 [2] 9f 28 [2] 9d 29 [2] 86 2f [2] 9a 28 [2] 86 07 }

  condition:
    any of them
}