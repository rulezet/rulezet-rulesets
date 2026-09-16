rule TTP_XOR_WriteProcessMemory_0f52 {
  strings:
    $key_0f52 = { 58 20 [2] 6a 02 [2] 6c 37 [2] 42 37 [2] 7d 2b }

  condition:
    any of them
}