rule TTP_XOR_QUAD_CurrentVersionRun_e87f {
  strings:
    $key_e87f = { bb 10 [2] 9f 1e [2] b4 32 [2] 9a 10 [2] 8e 0b [2] 81 11 [2] 9f 0c [2] 9d 0d [2] 86 0b [2] 9a 0c [2] 86 23 }

  condition:
    any of them
}