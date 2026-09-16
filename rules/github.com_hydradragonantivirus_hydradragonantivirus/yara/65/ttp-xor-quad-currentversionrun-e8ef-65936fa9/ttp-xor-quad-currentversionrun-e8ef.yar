rule TTP_XOR_QUAD_CurrentVersionRun_e8ef {
  strings:
    $key_e8ef = { bb 80 [2] 9f 8e [2] b4 a2 [2] 9a 80 [2] 8e 9b [2] 81 81 [2] 9f 9c [2] 9d 9d [2] 86 9b [2] 9a 9c [2] 86 b3 }

  condition:
    any of them
}