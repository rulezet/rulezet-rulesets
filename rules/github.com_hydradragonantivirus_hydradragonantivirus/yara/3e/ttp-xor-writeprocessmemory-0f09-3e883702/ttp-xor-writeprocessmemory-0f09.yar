rule TTP_XOR_WriteProcessMemory_0f09 {
  strings:
    $key_0f09 = { 58 7b [2] 6a 59 [2] 6c 6c [2] 42 6c [2] 7d 70 }

  condition:
    any of them
}