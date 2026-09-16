rule TTP_XOR_WriteProcessMemory_0f51 {
  strings:
    $key_0f51 = { 58 23 [2] 6a 01 [2] 6c 34 [2] 42 34 [2] 7d 28 }

  condition:
    any of them
}