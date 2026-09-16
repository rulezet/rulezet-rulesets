rule TTP_XOR_QUAD_CurrentVersionRun_7d7c {
  strings:
    $key_7d7c = { 2e 13 [2] 0a 1d [2] 21 31 [2] 0f 13 [2] 1b 08 [2] 14 12 [2] 0a 0f [2] 08 0e [2] 13 08 [2] 0f 0f [2] 13 20 }

  condition:
    any of them
}