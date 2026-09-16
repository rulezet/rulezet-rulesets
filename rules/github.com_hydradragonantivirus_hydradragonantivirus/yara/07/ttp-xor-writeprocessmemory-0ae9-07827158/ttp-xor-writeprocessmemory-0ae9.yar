rule TTP_XOR_WriteProcessMemory_0ae9 {
  strings:
    $key_0ae9 = { 5d 9b [2] 6f b9 [2] 69 8c [2] 47 8c [2] 78 90 }

  condition:
    any of them
}