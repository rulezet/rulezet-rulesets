rule TTP_XOR_WriteProcessMemory_0015 {
  strings:
    $key_0015 = { 57 67 [2] 65 45 [2] 63 70 [2] 4d 70 [2] 72 6c }

  condition:
    any of them
}