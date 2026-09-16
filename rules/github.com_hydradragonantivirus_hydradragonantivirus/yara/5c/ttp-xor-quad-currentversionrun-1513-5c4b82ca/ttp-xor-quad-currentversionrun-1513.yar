rule TTP_XOR_QUAD_CurrentVersionRun_1513 {
  strings:
    $key_1513 = { 46 7c [2] 62 72 [2] 49 5e [2] 67 7c [2] 73 67 [2] 7c 7d [2] 62 60 [2] 60 61 [2] 7b 67 [2] 67 60 [2] 7b 4f }

  condition:
    any of them
}