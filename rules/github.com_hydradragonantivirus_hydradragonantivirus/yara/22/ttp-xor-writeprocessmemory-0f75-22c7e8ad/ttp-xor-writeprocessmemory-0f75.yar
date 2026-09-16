rule TTP_XOR_WriteProcessMemory_0f75 {
  strings:
    $key_0f75 = { 58 07 [2] 6a 25 [2] 6c 10 [2] 42 10 [2] 7d 0c }

  condition:
    any of them
}