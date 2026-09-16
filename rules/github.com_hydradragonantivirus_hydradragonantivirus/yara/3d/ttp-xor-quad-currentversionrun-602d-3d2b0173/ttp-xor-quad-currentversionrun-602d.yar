rule TTP_XOR_QUAD_CurrentVersionRun_602d {
  strings:
    $key_602d = { 33 42 [2] 17 4c [2] 3c 60 [2] 12 42 [2] 06 59 [2] 09 43 [2] 17 5e [2] 15 5f [2] 0e 59 [2] 12 5e [2] 0e 71 }

  condition:
    any of them
}