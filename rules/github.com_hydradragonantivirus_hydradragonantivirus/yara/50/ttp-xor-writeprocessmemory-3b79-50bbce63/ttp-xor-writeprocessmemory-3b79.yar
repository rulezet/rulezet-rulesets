rule TTP_XOR_WriteProcessMemory_3b79 {
  strings:
    $key_3b79 = { 6c 0b [2] 5e 29 [2] 58 1c [2] 76 1c [2] 49 00 }

  condition:
    any of them
}