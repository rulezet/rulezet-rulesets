rule TTP_XOR_WriteProcessMemory_0f45 {
  strings:
    $key_0f45 = { 58 37 [2] 6a 15 [2] 6c 20 [2] 42 20 [2] 7d 3c }

  condition:
    any of them
}