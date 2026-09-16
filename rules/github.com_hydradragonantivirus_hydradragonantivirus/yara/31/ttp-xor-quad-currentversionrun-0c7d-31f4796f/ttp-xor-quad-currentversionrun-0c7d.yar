rule TTP_XOR_QUAD_CurrentVersionRun_0c7d {
  strings:
    $key_0c7d = { 5f 12 [2] 7b 1c [2] 50 30 [2] 7e 12 [2] 6a 09 [2] 65 13 [2] 7b 0e [2] 79 0f [2] 62 09 [2] 7e 0e [2] 62 21 }

  condition:
    any of them
}