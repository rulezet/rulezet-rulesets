rule TTP_XOR_QUAD_CurrentVersionRun_07ec {
  strings:
    $key_07ec = { 54 83 [2] 70 8d [2] 5b a1 [2] 75 83 [2] 61 98 [2] 6e 82 [2] 70 9f [2] 72 9e [2] 69 98 [2] 75 9f [2] 69 b0 }

  condition:
    any of them
}