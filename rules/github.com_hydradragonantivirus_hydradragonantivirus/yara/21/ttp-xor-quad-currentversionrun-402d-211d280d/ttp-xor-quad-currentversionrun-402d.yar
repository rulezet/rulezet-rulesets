rule TTP_XOR_QUAD_CurrentVersionRun_402d {
  strings:
    $key_402d = { 13 42 [2] 37 4c [2] 1c 60 [2] 32 42 [2] 26 59 [2] 29 43 [2] 37 5e [2] 35 5f [2] 2e 59 [2] 32 5e [2] 2e 71 }

  condition:
    any of them
}