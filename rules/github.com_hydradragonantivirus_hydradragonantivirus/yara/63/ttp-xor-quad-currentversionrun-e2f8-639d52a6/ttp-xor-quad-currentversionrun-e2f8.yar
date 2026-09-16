rule TTP_XOR_QUAD_CurrentVersionRun_e2f8 {
  strings:
    $key_e2f8 = { b1 97 [2] 95 99 [2] be b5 [2] 90 97 [2] 84 8c [2] 8b 96 [2] 95 8b [2] 97 8a [2] 8c 8c [2] 90 8b [2] 8c a4 }

  condition:
    any of them
}