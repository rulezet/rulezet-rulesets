rule TTP_XOR_WriteProcessMemory_5b46 {
  strings:
    $key_5b46 = { 0c 34 [2] 3e 16 [2] 38 23 [2] 16 23 [2] 29 3f }

  condition:
    any of them
}