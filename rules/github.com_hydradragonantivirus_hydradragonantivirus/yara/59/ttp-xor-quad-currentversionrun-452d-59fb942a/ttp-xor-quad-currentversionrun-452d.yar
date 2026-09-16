rule TTP_XOR_QUAD_CurrentVersionRun_452d {
  strings:
    $key_452d = { 16 42 [2] 32 4c [2] 19 60 [2] 37 42 [2] 23 59 [2] 2c 43 [2] 32 5e [2] 30 5f [2] 2b 59 [2] 37 5e [2] 2b 71 }

  condition:
    any of them
}