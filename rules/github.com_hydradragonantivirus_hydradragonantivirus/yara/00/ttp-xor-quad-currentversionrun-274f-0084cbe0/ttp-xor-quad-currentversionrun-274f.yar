rule TTP_XOR_QUAD_CurrentVersionRun_274f {
  strings:
    $key_274f = { 74 20 [2] 50 2e [2] 7b 02 [2] 55 20 [2] 41 3b [2] 4e 21 [2] 50 3c [2] 52 3d [2] 49 3b [2] 55 3c [2] 49 13 }

  condition:
    any of them
}