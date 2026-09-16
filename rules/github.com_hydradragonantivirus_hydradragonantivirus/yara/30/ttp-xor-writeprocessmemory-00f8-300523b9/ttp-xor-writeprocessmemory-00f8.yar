rule TTP_XOR_WriteProcessMemory_00f8 {
  strings:
    $key_00f8 = { 57 8a [2] 65 a8 [2] 63 9d [2] 4d 9d [2] 72 81 }

  condition:
    any of them
}