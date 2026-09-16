rule TTP_XOR_QUAD_CurrentVersionRun_1bec {
  strings:
    $key_1bec = { 48 83 [2] 6c 8d [2] 47 a1 [2] 69 83 [2] 7d 98 [2] 72 82 [2] 6c 9f [2] 6e 9e [2] 75 98 [2] 69 9f [2] 75 b0 }

  condition:
    any of them
}