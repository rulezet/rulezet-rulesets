rule TTP_XOR_QUAD_CurrentVersionRun_47ec {
  strings:
    $key_47ec = { 14 83 [2] 30 8d [2] 1b a1 [2] 35 83 [2] 21 98 [2] 2e 82 [2] 30 9f [2] 32 9e [2] 29 98 [2] 35 9f [2] 29 b0 }

  condition:
    any of them
}