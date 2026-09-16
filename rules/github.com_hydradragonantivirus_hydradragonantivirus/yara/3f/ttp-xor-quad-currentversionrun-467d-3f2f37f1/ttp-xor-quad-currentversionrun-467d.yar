rule TTP_XOR_QUAD_CurrentVersionRun_467d {
  strings:
    $key_467d = { 15 12 [2] 31 1c [2] 1a 30 [2] 34 12 [2] 20 09 [2] 2f 13 [2] 31 0e [2] 33 0f [2] 28 09 [2] 34 0e [2] 28 21 }

  condition:
    any of them
}