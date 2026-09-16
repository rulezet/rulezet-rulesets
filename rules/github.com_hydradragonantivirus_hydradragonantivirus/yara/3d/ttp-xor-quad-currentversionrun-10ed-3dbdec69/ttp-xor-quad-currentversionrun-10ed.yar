rule TTP_XOR_QUAD_CurrentVersionRun_10ed {
  strings:
    $key_10ed = { 43 82 [2] 67 8c [2] 4c a0 [2] 62 82 [2] 76 99 [2] 79 83 [2] 67 9e [2] 65 9f [2] 7e 99 [2] 62 9e [2] 7e b1 }

  condition:
    any of them
}