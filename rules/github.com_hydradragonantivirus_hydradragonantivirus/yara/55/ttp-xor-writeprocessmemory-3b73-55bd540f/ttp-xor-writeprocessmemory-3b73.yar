rule TTP_XOR_WriteProcessMemory_3b73 {
  strings:
    $key_3b73 = { 6c 01 [2] 5e 23 [2] 58 16 [2] 76 16 [2] 49 0a }

  condition:
    any of them
}