rule TTP_XOR_WriteProcessMemory_38d9 {
  strings:
    $key_38d9 = { 6f ab [2] 5d 89 [2] 5b bc [2] 75 bc [2] 4a a0 }

  condition:
    any of them
}