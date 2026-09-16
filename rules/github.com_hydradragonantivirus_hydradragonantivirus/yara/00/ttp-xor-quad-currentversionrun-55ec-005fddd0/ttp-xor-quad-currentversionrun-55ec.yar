rule TTP_XOR_QUAD_CurrentVersionRun_55ec {
  strings:
    $key_55ec = { 06 83 [2] 22 8d [2] 09 a1 [2] 27 83 [2] 33 98 [2] 3c 82 [2] 22 9f [2] 20 9e [2] 3b 98 [2] 27 9f [2] 3b b0 }

  condition:
    any of them
}