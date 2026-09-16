rule TTP_XOR_QUAD_CurrentVersionRun_4013 {
  strings:
    $key_4013 = { 13 7c [2] 37 72 [2] 1c 5e [2] 32 7c [2] 26 67 [2] 29 7d [2] 37 60 [2] 35 61 [2] 2e 67 [2] 32 60 [2] 2e 4f }

  condition:
    any of them
}