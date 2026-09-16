rule TTP_XOR_QUAD_CurrentVersionRun_25ec {
  strings:
    $key_25ec = { 76 83 [2] 52 8d [2] 79 a1 [2] 57 83 [2] 43 98 [2] 4c 82 [2] 52 9f [2] 50 9e [2] 4b 98 [2] 57 9f [2] 4b b0 }

  condition:
    any of them
}