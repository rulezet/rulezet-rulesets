rule TTP_XOR_QUAD_CurrentVersionRun_22ec {
  strings:
    $key_22ec = { 71 83 [2] 55 8d [2] 7e a1 [2] 50 83 [2] 44 98 [2] 4b 82 [2] 55 9f [2] 57 9e [2] 4c 98 [2] 50 9f [2] 4c b0 }

  condition:
    any of them
}