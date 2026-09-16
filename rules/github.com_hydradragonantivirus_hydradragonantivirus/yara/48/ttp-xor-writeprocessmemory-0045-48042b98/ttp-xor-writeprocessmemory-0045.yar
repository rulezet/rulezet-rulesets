rule TTP_XOR_WriteProcessMemory_0045 {
  strings:
    $key_0045 = { 57 37 [2] 65 15 [2] 63 20 [2] 4d 20 [2] 72 3c }

  condition:
    any of them
}