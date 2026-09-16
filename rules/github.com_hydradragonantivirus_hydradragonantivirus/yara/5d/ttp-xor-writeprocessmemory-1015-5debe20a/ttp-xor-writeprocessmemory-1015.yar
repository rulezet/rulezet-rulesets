rule TTP_XOR_WriteProcessMemory_1015 {
  strings:
    $key_1015 = { 47 67 [2] 75 45 [2] 73 70 [2] 5d 70 [2] 62 6c }

  condition:
    any of them
}