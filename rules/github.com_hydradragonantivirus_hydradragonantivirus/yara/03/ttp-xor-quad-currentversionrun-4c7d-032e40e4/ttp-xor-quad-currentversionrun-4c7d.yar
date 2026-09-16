rule TTP_XOR_QUAD_CurrentVersionRun_4c7d {
  strings:
    $key_4c7d = { 1f 12 [2] 3b 1c [2] 10 30 [2] 3e 12 [2] 2a 09 [2] 25 13 [2] 3b 0e [2] 39 0f [2] 22 09 [2] 3e 0e [2] 22 21 }

  condition:
    any of them
}