rule TTP_XOR_QUAD_CurrentVersionRun_497d {
  strings:
    $key_497d = { 1a 12 [2] 3e 1c [2] 15 30 [2] 3b 12 [2] 2f 09 [2] 20 13 [2] 3e 0e [2] 3c 0f [2] 27 09 [2] 3b 0e [2] 27 21 }

  condition:
    any of them
}