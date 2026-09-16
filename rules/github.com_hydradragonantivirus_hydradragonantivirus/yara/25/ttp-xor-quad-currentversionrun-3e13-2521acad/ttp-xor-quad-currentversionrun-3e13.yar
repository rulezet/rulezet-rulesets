rule TTP_XOR_QUAD_CurrentVersionRun_3e13 {
  strings:
    $key_3e13 = { 6d 7c [2] 49 72 [2] 62 5e [2] 4c 7c [2] 58 67 [2] 57 7d [2] 49 60 [2] 4b 61 [2] 50 67 [2] 4c 60 [2] 50 4f }

  condition:
    any of them
}