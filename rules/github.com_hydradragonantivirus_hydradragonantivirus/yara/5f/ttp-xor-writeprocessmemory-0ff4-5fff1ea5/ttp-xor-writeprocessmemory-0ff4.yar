rule TTP_XOR_WriteProcessMemory_0ff4 {
  strings:
    $key_0ff4 = { 58 86 [2] 6a a4 [2] 6c 91 [2] 42 91 [2] 7d 8d }

  condition:
    any of them
}