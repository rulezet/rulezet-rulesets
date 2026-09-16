rule TTP_XOR_WriteProcessMemory_4515 {
  strings:
    $key_4515 = { 12 67 [2] 20 45 [2] 26 70 [2] 08 70 [2] 37 6c }

  condition:
    any of them
}