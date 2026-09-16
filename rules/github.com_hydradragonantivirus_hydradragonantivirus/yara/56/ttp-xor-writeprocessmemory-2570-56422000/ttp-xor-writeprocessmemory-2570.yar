rule TTP_XOR_WriteProcessMemory_2570 {
  strings:
    $key_2570 = { 72 02 [2] 40 20 [2] 46 15 [2] 68 15 [2] 57 09 }

  condition:
    any of them
}