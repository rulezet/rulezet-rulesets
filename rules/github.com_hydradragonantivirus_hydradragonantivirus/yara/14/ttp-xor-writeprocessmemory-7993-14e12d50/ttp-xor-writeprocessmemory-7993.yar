rule TTP_XOR_WriteProcessMemory_7993 {
  strings:
    $key_7993 = { 2e e1 [2] 1c c3 [2] 1a f6 [2] 34 f6 [2] 0b ea }

  condition:
    any of them
}