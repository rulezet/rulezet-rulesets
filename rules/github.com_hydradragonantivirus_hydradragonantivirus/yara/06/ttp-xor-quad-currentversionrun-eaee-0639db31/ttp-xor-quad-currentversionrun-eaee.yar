rule TTP_XOR_QUAD_CurrentVersionRun_eaee {
  strings:
    $key_eaee = { b9 81 [2] 9d 8f [2] b6 a3 [2] 98 81 [2] 8c 9a [2] 83 80 [2] 9d 9d [2] 9f 9c [2] 84 9a [2] 98 9d [2] 84 b2 }

  condition:
    any of them
}