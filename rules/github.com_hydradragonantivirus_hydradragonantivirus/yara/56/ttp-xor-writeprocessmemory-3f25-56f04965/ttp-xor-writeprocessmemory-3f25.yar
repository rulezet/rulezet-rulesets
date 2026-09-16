rule TTP_XOR_WriteProcessMemory_3f25 {
  strings:
    $key_3f25 = { 68 57 [2] 5a 75 [2] 5c 40 [2] 72 40 [2] 4d 5c }

  condition:
    any of them
}