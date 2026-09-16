rule TTP_XOR_WriteProcessMemory_2ee9 {
  strings:
    $key_2ee9 = { 79 9b [2] 4b b9 [2] 4d 8c [2] 63 8c [2] 5c 90 }

  condition:
    any of them
}