rule TTP_XOR_QUAD_CurrentVersionRun_22ed {
  strings:
    $key_22ed = { 71 82 [2] 55 8c [2] 7e a0 [2] 50 82 [2] 44 99 [2] 4b 83 [2] 55 9e [2] 57 9f [2] 4c 99 [2] 50 9e [2] 4c b1 }

  condition:
    any of them
}