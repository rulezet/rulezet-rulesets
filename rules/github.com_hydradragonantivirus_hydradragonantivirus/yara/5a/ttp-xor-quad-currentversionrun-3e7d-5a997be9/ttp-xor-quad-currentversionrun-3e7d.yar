rule TTP_XOR_QUAD_CurrentVersionRun_3e7d {
  strings:
    $key_3e7d = { 6d 12 [2] 49 1c [2] 62 30 [2] 4c 12 [2] 58 09 [2] 57 13 [2] 49 0e [2] 4b 0f [2] 50 09 [2] 4c 0e [2] 50 21 }

  condition:
    any of them
}