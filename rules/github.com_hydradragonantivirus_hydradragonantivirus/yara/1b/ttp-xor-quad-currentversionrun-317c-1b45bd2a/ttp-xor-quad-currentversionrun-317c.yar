rule TTP_XOR_QUAD_CurrentVersionRun_317c {
  strings:
    $key_317c = { 62 13 [2] 46 1d [2] 6d 31 [2] 43 13 [2] 57 08 [2] 58 12 [2] 46 0f [2] 44 0e [2] 5f 08 [2] 43 0f [2] 5f 20 }

  condition:
    any of them
}