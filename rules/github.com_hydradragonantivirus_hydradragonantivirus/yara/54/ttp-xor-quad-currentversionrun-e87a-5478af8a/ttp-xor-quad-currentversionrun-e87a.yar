rule TTP_XOR_QUAD_CurrentVersionRun_e87a {
  strings:
    $key_e87a = { bb 15 [2] 9f 1b [2] b4 37 [2] 9a 15 [2] 8e 0e [2] 81 14 [2] 9f 09 [2] 9d 08 [2] 86 0e [2] 9a 09 [2] 86 26 }

  condition:
    any of them
}