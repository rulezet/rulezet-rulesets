rule TTP_XOR_WriteProcessMemory_0845 {
  strings:
    $key_0845 = { 5f 37 [2] 6d 15 [2] 6b 20 [2] 45 20 [2] 7a 3c }

  condition:
    any of them
}