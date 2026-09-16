rule TTP_XOR_WriteProcessMemory_0835 {
  strings:
    $key_0835 = { 5f 47 [2] 6d 65 [2] 6b 50 [2] 45 50 [2] 7a 4c }

  condition:
    any of them
}