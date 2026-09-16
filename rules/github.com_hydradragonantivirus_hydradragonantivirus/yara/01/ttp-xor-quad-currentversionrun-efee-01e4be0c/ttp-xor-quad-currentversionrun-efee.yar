rule TTP_XOR_QUAD_CurrentVersionRun_efee {
  strings:
    $key_efee = { bc 81 [2] 98 8f [2] b3 a3 [2] 9d 81 [2] 89 9a [2] 86 80 [2] 98 9d [2] 9a 9c [2] 81 9a [2] 9d 9d [2] 81 b2 }

  condition:
    any of them
}