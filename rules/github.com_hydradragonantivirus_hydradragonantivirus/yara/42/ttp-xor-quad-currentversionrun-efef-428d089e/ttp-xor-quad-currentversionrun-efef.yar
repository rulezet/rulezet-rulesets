rule TTP_XOR_QUAD_CurrentVersionRun_efef {
  strings:
    $key_efef = { bc 80 [2] 98 8e [2] b3 a2 [2] 9d 80 [2] 89 9b [2] 86 81 [2] 98 9c [2] 9a 9d [2] 81 9b [2] 9d 9c [2] 81 b3 }

  condition:
    any of them
}