rule TTP_XOR_WriteProcessMemory_0f70 {
  strings:
    $key_0f70 = { 58 02 [2] 6a 20 [2] 6c 15 [2] 42 15 [2] 7d 09 }

  condition:
    any of them
}