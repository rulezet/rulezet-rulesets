rule TTP_XOR_QUAD_CurrentVersionRun_492d {
  strings:
    $key_492d = { 1a 42 [2] 3e 4c [2] 15 60 [2] 3b 42 [2] 2f 59 [2] 20 43 [2] 3e 5e [2] 3c 5f [2] 27 59 [2] 3b 5e [2] 27 71 }

  condition:
    any of them
}