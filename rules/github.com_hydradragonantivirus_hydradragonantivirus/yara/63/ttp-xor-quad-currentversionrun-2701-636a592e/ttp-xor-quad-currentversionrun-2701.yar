rule TTP_XOR_QUAD_CurrentVersionRun_2701 {
  strings:
    $key_2701 = { 74 6e [2] 50 60 [2] 7b 4c [2] 55 6e [2] 41 75 [2] 4e 6f [2] 50 72 [2] 52 73 [2] 49 75 [2] 55 72 [2] 49 5d }

  condition:
    any of them
}