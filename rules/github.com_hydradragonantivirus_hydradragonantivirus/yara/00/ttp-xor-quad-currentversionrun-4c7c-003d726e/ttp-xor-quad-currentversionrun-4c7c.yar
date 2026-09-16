rule TTP_XOR_QUAD_CurrentVersionRun_4c7c {
  strings:
    $key_4c7c = { 1f 13 [2] 3b 1d [2] 10 31 [2] 3e 13 [2] 2a 08 [2] 25 12 [2] 3b 0f [2] 39 0e [2] 22 08 [2] 3e 0f [2] 22 20 }

  condition:
    any of them
}