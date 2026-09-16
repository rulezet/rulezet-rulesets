rule TTP_XOR_QUAD_CurrentVersionRun_492c {
  strings:
    $key_492c = { 1a 43 [2] 3e 4d [2] 15 61 [2] 3b 43 [2] 2f 58 [2] 20 42 [2] 3e 5f [2] 3c 5e [2] 27 58 [2] 3b 5f [2] 27 70 }

  condition:
    any of them
}