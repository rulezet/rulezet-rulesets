rule TTP_XOR_WriteProcessMemory_6730 {
  strings:
    $key_6730 = { 30 42 [2] 02 60 [2] 04 55 [2] 2a 55 [2] 15 49 }

  condition:
    any of them
}