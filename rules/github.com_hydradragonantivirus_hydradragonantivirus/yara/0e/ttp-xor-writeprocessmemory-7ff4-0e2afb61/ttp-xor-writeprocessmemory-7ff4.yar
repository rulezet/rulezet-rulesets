rule TTP_XOR_WriteProcessMemory_7ff4 {
  strings:
    $key_7ff4 = { 28 86 [2] 1a a4 [2] 1c 91 [2] 32 91 [2] 0d 8d }

  condition:
    any of them
}