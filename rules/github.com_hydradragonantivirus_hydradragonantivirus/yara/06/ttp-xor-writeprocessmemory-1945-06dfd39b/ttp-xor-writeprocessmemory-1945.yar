rule TTP_XOR_WriteProcessMemory_1945 {
  strings:
    $key_1945 = { 4e 37 [2] 7c 15 [2] 7a 20 [2] 54 20 [2] 6b 3c }

  condition:
    any of them
}