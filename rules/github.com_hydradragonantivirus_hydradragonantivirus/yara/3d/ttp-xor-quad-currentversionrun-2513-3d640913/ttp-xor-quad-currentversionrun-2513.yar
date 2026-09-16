rule TTP_XOR_QUAD_CurrentVersionRun_2513 {
  strings:
    $key_2513 = { 76 7c [2] 52 72 [2] 79 5e [2] 57 7c [2] 43 67 [2] 4c 7d [2] 52 60 [2] 50 61 [2] 4b 67 [2] 57 60 [2] 4b 4f }

  condition:
    any of them
}