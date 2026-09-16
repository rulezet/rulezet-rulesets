rule TTP_XOR_WriteProcessMemory_00e7 {
  strings:
    $key_00e7 = { 57 95 [2] 65 b7 [2] 63 82 [2] 4d 82 [2] 72 9e }

  condition:
    any of them
}