rule TTP_XOR_WriteProcessMemory_3945 {
  strings:
    $key_3945 = { 6e 37 [2] 5c 15 [2] 5a 20 [2] 74 20 [2] 4b 3c }

  condition:
    any of them
}