rule TTP_XOR_WriteProcessMemory_1ce9 {
  strings:
    $key_1ce9 = { 4b 9b [2] 79 b9 [2] 7f 8c [2] 51 8c [2] 6e 90 }

  condition:
    any of them
}