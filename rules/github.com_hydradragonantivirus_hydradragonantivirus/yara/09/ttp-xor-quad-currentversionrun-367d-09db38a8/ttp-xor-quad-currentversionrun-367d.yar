rule TTP_XOR_QUAD_CurrentVersionRun_367d {
  strings:
    $key_367d = { 65 12 [2] 41 1c [2] 6a 30 [2] 44 12 [2] 50 09 [2] 5f 13 [2] 41 0e [2] 43 0f [2] 58 09 [2] 44 0e [2] 58 21 }

  condition:
    any of them
}