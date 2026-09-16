rule TTP_XOR_WriteProcessMemory_00f9 {
  strings:
    $key_00f9 = { 57 8b [2] 65 a9 [2] 63 9c [2] 4d 9c [2] 72 80 }

  condition:
    any of them
}