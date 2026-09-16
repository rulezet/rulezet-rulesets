rule TTP_XOR_QUAD_CurrentVersionRun_f1ed {
  strings:
    $key_f1ed = { a2 82 [2] 86 8c [2] ad a0 [2] 83 82 [2] 97 99 [2] 98 83 [2] 86 9e [2] 84 9f [2] 9f 99 [2] 83 9e [2] 9f b1 }

  condition:
    any of them
}