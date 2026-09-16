rule TTP_XOR_QUAD_CurrentVersionRun_4c7b {
  strings:
    $key_4c7b = { 1f 14 [2] 3b 1a [2] 10 36 [2] 3e 14 [2] 2a 0f [2] 25 15 [2] 3b 08 [2] 39 09 [2] 22 0f [2] 3e 08 [2] 22 27 }

  condition:
    any of them
}