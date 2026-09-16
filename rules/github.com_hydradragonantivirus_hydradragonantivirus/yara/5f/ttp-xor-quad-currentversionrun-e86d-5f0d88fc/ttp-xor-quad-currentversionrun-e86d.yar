rule TTP_XOR_QUAD_CurrentVersionRun_e86d {
  strings:
    $key_e86d = { bb 02 [2] 9f 0c [2] b4 20 [2] 9a 02 [2] 8e 19 [2] 81 03 [2] 9f 1e [2] 9d 1f [2] 86 19 [2] 9a 1e [2] 86 31 }

  condition:
    any of them
}