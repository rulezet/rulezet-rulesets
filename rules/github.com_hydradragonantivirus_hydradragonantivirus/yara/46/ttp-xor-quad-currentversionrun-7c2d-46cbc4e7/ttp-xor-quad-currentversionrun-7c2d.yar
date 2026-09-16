rule TTP_XOR_QUAD_CurrentVersionRun_7c2d {
  strings:
    $key_7c2d = { 2f 42 [2] 0b 4c [2] 20 60 [2] 0e 42 [2] 1a 59 [2] 15 43 [2] 0b 5e [2] 09 5f [2] 12 59 [2] 0e 5e [2] 12 71 }

  condition:
    any of them
}