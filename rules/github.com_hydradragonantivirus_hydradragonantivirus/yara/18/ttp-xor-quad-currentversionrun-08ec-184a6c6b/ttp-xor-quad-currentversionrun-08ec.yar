rule TTP_XOR_QUAD_CurrentVersionRun_08ec {
  strings:
    $key_08ec = { 5b 83 [2] 7f 8d [2] 54 a1 [2] 7a 83 [2] 6e 98 [2] 61 82 [2] 7f 9f [2] 7d 9e [2] 66 98 [2] 7a 9f [2] 66 b0 }

  condition:
    any of them
}