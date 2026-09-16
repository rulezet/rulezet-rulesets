rule TTP_XOR_WriteProcessMemory_38e9 {
  strings:
    $key_38e9 = { 6f 9b [2] 5d b9 [2] 5b 8c [2] 75 8c [2] 4a 90 }

  condition:
    any of them
}