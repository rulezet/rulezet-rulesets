rule TTP_XOR_WriteProcessMemory_3883 {
  strings:
    $key_3883 = { 6f f1 [2] 5d d3 [2] 5b e6 [2] 75 e6 [2] 4a fa }

  condition:
    any of them
}