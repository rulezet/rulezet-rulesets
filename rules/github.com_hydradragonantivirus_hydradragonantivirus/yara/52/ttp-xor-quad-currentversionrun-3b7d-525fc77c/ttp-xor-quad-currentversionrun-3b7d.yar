rule TTP_XOR_QUAD_CurrentVersionRun_3b7d {
  strings:
    $key_3b7d = { 68 12 [2] 4c 1c [2] 67 30 [2] 49 12 [2] 5d 09 [2] 52 13 [2] 4c 0e [2] 4e 0f [2] 55 09 [2] 49 0e [2] 55 21 }

  condition:
    any of them
}