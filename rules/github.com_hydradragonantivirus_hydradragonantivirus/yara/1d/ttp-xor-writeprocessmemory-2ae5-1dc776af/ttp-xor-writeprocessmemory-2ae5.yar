rule TTP_XOR_WriteProcessMemory_2ae5 {
  strings:
    $key_2ae5 = { 7d 97 [2] 4f b5 [2] 49 80 [2] 67 80 [2] 58 9c }

  condition:
    any of them
}