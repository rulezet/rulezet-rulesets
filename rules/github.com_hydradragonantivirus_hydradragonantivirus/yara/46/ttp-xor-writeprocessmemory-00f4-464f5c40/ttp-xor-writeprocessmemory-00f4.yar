rule TTP_XOR_WriteProcessMemory_00f4 {
  strings:
    $key_00f4 = { 57 86 [2] 65 a4 [2] 63 91 [2] 4d 91 [2] 72 8d }

  condition:
    any of them
}