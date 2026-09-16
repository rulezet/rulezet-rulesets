rule TTP_XOR_QUAD_CurrentVersionRun_4033 {
  strings:
    $key_4033 = { 13 5c [2] 37 52 [2] 1c 7e [2] 32 5c [2] 26 47 [2] 29 5d [2] 37 40 [2] 35 41 [2] 2e 47 [2] 32 40 [2] 2e 6f }

  condition:
    any of them
}