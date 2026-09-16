rule TTP_XOR_WriteProcessMemory_65f4 {
  strings:
    $key_65f4 = { 32 86 [2] 00 a4 [2] 06 91 [2] 28 91 [2] 17 8d }

  condition:
    any of them
}