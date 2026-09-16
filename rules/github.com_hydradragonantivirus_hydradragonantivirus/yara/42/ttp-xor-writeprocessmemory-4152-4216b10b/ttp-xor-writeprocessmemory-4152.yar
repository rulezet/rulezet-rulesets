rule TTP_XOR_WriteProcessMemory_4152 {
  strings:
    $key_4152 = { 16 20 [2] 24 02 [2] 22 37 [2] 0c 37 [2] 33 2b }

  condition:
    any of them
}