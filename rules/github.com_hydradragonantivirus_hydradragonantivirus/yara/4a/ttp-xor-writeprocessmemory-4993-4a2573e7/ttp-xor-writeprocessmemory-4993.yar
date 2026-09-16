rule TTP_XOR_WriteProcessMemory_4993 {
  strings:
    $key_4993 = { 1e e1 [2] 2c c3 [2] 2a f6 [2] 04 f6 [2] 3b ea }

  condition:
    any of them
}