rule TTP_XOR_QUAD_CurrentVersionRun_1501 {
  strings:
    $key_1501 = { 46 6e [2] 62 60 [2] 49 4c [2] 67 6e [2] 73 75 [2] 7c 6f [2] 62 72 [2] 60 73 [2] 7b 75 [2] 67 72 [2] 7b 5d }

  condition:
    any of them
}