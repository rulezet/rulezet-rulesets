rule TTP_XOR_QUAD_CurrentVersionRun_e86a {
  strings:
    $key_e86a = { bb 05 [2] 9f 0b [2] b4 27 [2] 9a 05 [2] 8e 1e [2] 81 04 [2] 9f 19 [2] 9d 18 [2] 86 1e [2] 9a 19 [2] 86 36 }

  condition:
    any of them
}