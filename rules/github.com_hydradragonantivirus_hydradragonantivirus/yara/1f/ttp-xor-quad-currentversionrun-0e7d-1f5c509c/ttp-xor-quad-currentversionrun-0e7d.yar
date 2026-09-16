rule TTP_XOR_QUAD_CurrentVersionRun_0e7d {
  strings:
    $key_0e7d = { 5d 12 [2] 79 1c [2] 52 30 [2] 7c 12 [2] 68 09 [2] 67 13 [2] 79 0e [2] 7b 0f [2] 60 09 [2] 7c 0e [2] 60 21 }

  condition:
    any of them
}