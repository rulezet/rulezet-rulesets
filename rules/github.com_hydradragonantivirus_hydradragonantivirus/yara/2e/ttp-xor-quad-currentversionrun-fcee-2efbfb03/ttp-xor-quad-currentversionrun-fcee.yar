rule TTP_XOR_QUAD_CurrentVersionRun_fcee {
  strings:
    $key_fcee = { af 81 [2] 8b 8f [2] a0 a3 [2] 8e 81 [2] 9a 9a [2] 95 80 [2] 8b 9d [2] 89 9c [2] 92 9a [2] 8e 9d [2] 92 b2 }

  condition:
    any of them
}