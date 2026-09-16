rule TTP_XOR_QUAD_CurrentVersionRun_47ed {
  strings:
    $key_47ed = { 14 82 [2] 30 8c [2] 1b a0 [2] 35 82 [2] 21 99 [2] 2e 83 [2] 30 9e [2] 32 9f [2] 29 99 [2] 35 9e [2] 29 b1 }

  condition:
    any of them
}