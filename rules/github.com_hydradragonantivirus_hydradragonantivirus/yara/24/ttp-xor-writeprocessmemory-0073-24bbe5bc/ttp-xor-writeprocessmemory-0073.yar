rule TTP_XOR_WriteProcessMemory_0073 {
  strings:
    $key_0073 = { 57 01 [2] 65 23 [2] 63 16 [2] 4d 16 [2] 72 0a }

  condition:
    any of them
}