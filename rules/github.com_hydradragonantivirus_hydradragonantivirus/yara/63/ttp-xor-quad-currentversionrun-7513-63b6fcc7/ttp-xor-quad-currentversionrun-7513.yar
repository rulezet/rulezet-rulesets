rule TTP_XOR_QUAD_CurrentVersionRun_7513 {
  strings:
    $key_7513 = { 26 7c [2] 02 72 [2] 29 5e [2] 07 7c [2] 13 67 [2] 1c 7d [2] 02 60 [2] 00 61 [2] 1b 67 [2] 07 60 [2] 1b 4f }

  condition:
    any of them
}