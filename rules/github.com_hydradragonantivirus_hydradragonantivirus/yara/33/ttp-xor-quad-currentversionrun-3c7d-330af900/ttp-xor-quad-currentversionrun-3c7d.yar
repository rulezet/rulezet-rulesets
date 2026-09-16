rule TTP_XOR_QUAD_CurrentVersionRun_3c7d {
  strings:
    $key_3c7d = { 6f 12 [2] 4b 1c [2] 60 30 [2] 4e 12 [2] 5a 09 [2] 55 13 [2] 4b 0e [2] 49 0f [2] 52 09 [2] 4e 0e [2] 52 21 }

  condition:
    any of them
}