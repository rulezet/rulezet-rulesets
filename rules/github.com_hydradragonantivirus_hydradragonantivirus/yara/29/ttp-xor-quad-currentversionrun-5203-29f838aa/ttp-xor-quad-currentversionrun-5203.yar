rule TTP_XOR_QUAD_CurrentVersionRun_5203 {
  strings:
    $key_5203 = { 01 6c [2] 25 62 [2] 0e 4e [2] 20 6c [2] 34 77 [2] 3b 6d [2] 25 70 [2] 27 71 [2] 3c 77 [2] 20 70 [2] 3c 5f }

  condition:
    any of them
}