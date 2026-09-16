rule TTP_XOR_QUAD_CurrentVersionRun_f1ef {
  strings:
    $key_f1ef = { a2 80 [2] 86 8e [2] ad a2 [2] 83 80 [2] 97 9b [2] 98 81 [2] 86 9c [2] 84 9d [2] 9f 9b [2] 83 9c [2] 9f b3 }

  condition:
    any of them
}