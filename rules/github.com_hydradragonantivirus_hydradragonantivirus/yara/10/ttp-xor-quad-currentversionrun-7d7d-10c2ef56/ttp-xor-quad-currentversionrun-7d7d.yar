rule TTP_XOR_QUAD_CurrentVersionRun_7d7d {
  strings:
    $key_7d7d = { 2e 12 [2] 0a 1c [2] 21 30 [2] 0f 12 [2] 1b 09 [2] 14 13 [2] 0a 0e [2] 08 0f [2] 13 09 [2] 0f 0e [2] 13 21 }

  condition:
    any of them
}