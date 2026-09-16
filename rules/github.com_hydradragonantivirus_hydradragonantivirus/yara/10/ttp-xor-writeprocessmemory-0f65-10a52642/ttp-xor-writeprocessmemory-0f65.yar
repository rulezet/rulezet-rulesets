rule TTP_XOR_WriteProcessMemory_0f65 {
  strings:
    $key_0f65 = { 58 17 [2] 6a 35 [2] 6c 00 [2] 42 00 [2] 7d 1c }

  condition:
    any of them
}