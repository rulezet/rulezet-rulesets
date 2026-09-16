rule TTP_XOR_QUAD_CurrentVersionRun_e836 {
  strings:
    $key_e836 = { bb 59 [2] 9f 57 [2] b4 7b [2] 9a 59 [2] 8e 42 [2] 81 58 [2] 9f 45 [2] 9d 44 [2] 86 42 [2] 9a 45 [2] 86 6a }

  condition:
    any of them
}