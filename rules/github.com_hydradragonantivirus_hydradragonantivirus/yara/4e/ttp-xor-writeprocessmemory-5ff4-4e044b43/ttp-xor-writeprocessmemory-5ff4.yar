rule TTP_XOR_WriteProcessMemory_5ff4 {
  strings:
    $key_5ff4 = { 08 86 [2] 3a a4 [2] 3c 91 [2] 12 91 [2] 2d 8d }

  condition:
    any of them
}