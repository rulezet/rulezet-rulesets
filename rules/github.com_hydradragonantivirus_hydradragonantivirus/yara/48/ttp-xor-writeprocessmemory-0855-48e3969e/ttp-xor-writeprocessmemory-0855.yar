rule TTP_XOR_WriteProcessMemory_0855 {
  strings:
    $key_0855 = { 5f 27 [2] 6d 05 [2] 6b 30 [2] 45 30 [2] 7a 2c }

  condition:
    any of them
}