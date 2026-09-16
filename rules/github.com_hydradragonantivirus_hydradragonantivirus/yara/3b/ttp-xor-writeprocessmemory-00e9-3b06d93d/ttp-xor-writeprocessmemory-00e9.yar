rule TTP_XOR_WriteProcessMemory_00e9 {
  strings:
    $key_00e9 = { 57 9b [2] 65 b9 [2] 63 8c [2] 4d 8c [2] 72 90 }

  condition:
    any of them
}