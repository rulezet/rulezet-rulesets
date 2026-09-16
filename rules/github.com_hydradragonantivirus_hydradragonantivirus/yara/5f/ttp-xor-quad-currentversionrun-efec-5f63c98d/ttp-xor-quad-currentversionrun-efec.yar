rule TTP_XOR_QUAD_CurrentVersionRun_efec {
  strings:
    $key_efec = { bc 83 [2] 98 8d [2] b3 a1 [2] 9d 83 [2] 89 98 [2] 86 82 [2] 98 9f [2] 9a 9e [2] 81 98 [2] 9d 9f [2] 81 b0 }

  condition:
    any of them
}