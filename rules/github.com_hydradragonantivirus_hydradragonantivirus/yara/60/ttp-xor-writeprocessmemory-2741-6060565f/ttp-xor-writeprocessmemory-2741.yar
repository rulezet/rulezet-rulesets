rule TTP_XOR_WriteProcessMemory_2741 {
  strings:
    $key_2741 = { 70 33 [2] 42 11 [2] 44 24 [2] 6a 24 [2] 55 38 }

  condition:
    any of them
}