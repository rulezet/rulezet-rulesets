rule TTP_XOR_QUAD_CurrentVersionRun_e2f2 {
  strings:
    $key_e2f2 = { b1 9d [2] 95 93 [2] be bf [2] 90 9d [2] 84 86 [2] 8b 9c [2] 95 81 [2] 97 80 [2] 8c 86 [2] 90 81 [2] 8c ae }

  condition:
    any of them
}