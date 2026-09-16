rule TTP_XOR_QUAD_CurrentVersionRun_5213 {
  strings:
    $key_5213 = { 01 7c [2] 25 72 [2] 0e 5e [2] 20 7c [2] 34 67 [2] 3b 7d [2] 25 60 [2] 27 61 [2] 3c 67 [2] 20 60 [2] 3c 4f }

  condition:
    any of them
}