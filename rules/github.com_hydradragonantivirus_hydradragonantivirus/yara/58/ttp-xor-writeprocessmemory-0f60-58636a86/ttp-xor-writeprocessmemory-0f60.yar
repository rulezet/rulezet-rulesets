rule TTP_XOR_WriteProcessMemory_0f60 {
  strings:
    $key_0f60 = { 58 12 [2] 6a 30 [2] 6c 05 [2] 42 05 [2] 7d 19 }

  condition:
    any of them
}