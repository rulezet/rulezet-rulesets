rule TTP_XOR_QUAD_CurrentVersionRun_e2f4 {
  strings:
    $key_e2f4 = { b1 9b [2] 95 95 [2] be b9 [2] 90 9b [2] 84 80 [2] 8b 9a [2] 95 87 [2] 97 86 [2] 8c 80 [2] 90 87 [2] 8c a8 }

  condition:
    any of them
}