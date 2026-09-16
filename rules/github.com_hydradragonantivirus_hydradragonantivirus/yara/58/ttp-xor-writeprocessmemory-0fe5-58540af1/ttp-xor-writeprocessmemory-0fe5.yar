rule TTP_XOR_WriteProcessMemory_0fe5 {
  strings:
    $key_0fe5 = { 58 97 [2] 6a b5 [2] 6c 80 [2] 42 80 [2] 7d 9c }

  condition:
    any of them
}