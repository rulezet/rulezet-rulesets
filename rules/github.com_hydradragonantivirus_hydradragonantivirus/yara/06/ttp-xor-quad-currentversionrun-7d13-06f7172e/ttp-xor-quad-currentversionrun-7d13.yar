rule TTP_XOR_QUAD_CurrentVersionRun_7d13 {
  strings:
    $key_7d13 = { 2e 7c [2] 0a 72 [2] 21 5e [2] 0f 7c [2] 1b 67 [2] 14 7d [2] 0a 60 [2] 08 61 [2] 13 67 [2] 0f 60 [2] 13 4f }

  condition:
    any of them
}