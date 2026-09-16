rule TTP_XOR_QUAD_CurrentVersionRun_31ed {
  strings:
    $key_31ed = { 62 82 [2] 46 8c [2] 6d a0 [2] 43 82 [2] 57 99 [2] 58 83 [2] 46 9e [2] 44 9f [2] 5f 99 [2] 43 9e [2] 5f b1 }

  condition:
    any of them
}