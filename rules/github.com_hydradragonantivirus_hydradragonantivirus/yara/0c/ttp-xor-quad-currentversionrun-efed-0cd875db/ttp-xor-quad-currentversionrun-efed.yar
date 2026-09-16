rule TTP_XOR_QUAD_CurrentVersionRun_efed {
  strings:
    $key_efed = { bc 82 [2] 98 8c [2] b3 a0 [2] 9d 82 [2] 89 99 [2] 86 83 [2] 98 9e [2] 9a 9f [2] 81 99 [2] 9d 9e [2] 81 b1 }

  condition:
    any of them
}