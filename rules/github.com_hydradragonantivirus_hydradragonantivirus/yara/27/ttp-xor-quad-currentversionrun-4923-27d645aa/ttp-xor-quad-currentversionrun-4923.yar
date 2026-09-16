rule TTP_XOR_QUAD_CurrentVersionRun_4923 {
  strings:
    $key_4923 = { 1a 4c [2] 3e 42 [2] 15 6e [2] 3b 4c [2] 2f 57 [2] 20 4d [2] 3e 50 [2] 3c 51 [2] 27 57 [2] 3b 50 [2] 27 7f }

  condition:
    any of them
}