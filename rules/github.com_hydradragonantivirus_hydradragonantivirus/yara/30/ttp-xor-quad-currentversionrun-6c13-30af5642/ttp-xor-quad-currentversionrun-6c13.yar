rule TTP_XOR_QUAD_CurrentVersionRun_6c13 {
  strings:
    $key_6c13 = { 3f 7c [2] 1b 72 [2] 30 5e [2] 1e 7c [2] 0a 67 [2] 05 7d [2] 1b 60 [2] 19 61 [2] 02 67 [2] 1e 60 [2] 02 4f }

  condition:
    any of them
}