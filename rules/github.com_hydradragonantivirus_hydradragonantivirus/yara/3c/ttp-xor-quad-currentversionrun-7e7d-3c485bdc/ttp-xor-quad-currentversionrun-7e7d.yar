rule TTP_XOR_QUAD_CurrentVersionRun_7e7d {
  strings:
    $key_7e7d = { 2d 12 [2] 09 1c [2] 22 30 [2] 0c 12 [2] 18 09 [2] 17 13 [2] 09 0e [2] 0b 0f [2] 10 09 [2] 0c 0e [2] 10 21 }

  condition:
    any of them
}