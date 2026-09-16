rule TTP_XOR_QUAD_CurrentVersionRun_e82b {
  strings:
    $key_e82b = { bb 44 [2] 9f 4a [2] b4 66 [2] 9a 44 [2] 8e 5f [2] 81 45 [2] 9f 58 [2] 9d 59 [2] 86 5f [2] 9a 58 [2] 86 77 }

  condition:
    any of them
}