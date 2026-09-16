rule TTP_XOR_QUAD_CurrentVersionRun_4733 {
  strings:
    $key_4733 = { 14 5c [2] 30 52 [2] 1b 7e [2] 35 5c [2] 21 47 [2] 2e 5d [2] 30 40 [2] 32 41 [2] 29 47 [2] 35 40 [2] 29 6f }

  condition:
    any of them
}