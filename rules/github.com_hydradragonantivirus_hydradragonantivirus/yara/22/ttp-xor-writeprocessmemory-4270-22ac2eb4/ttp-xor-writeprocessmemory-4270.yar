rule TTP_XOR_WriteProcessMemory_4270 {
  strings:
    $key_4270 = { 15 02 [2] 27 20 [2] 21 15 [2] 0f 15 [2] 30 09 }

  condition:
    any of them
}