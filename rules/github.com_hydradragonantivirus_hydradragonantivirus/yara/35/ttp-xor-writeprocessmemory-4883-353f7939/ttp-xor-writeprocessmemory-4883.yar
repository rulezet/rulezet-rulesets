rule TTP_XOR_WriteProcessMemory_4883 {
  strings:
    $key_4883 = { 1f f1 [2] 2d d3 [2] 2b e6 [2] 05 e6 [2] 3a fa }

  condition:
    any of them
}