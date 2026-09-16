rule TTP_XOR_WriteProcessMemory_2af5 {
  strings:
    $key_2af5 = { 7d 87 [2] 4f a5 [2] 49 90 [2] 67 90 [2] 58 8c }

  condition:
    any of them
}