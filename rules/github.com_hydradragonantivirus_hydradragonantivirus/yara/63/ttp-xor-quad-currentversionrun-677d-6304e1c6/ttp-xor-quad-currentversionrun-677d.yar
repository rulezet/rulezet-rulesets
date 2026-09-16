rule TTP_XOR_QUAD_CurrentVersionRun_677d {
  strings:
    $key_677d = { 34 12 [2] 10 1c [2] 3b 30 [2] 15 12 [2] 01 09 [2] 0e 13 [2] 10 0e [2] 12 0f [2] 09 09 [2] 15 0e [2] 09 21 }

  condition:
    any of them
}