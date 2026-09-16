rule TTP_XOR_WriteProcessMemory_1993 {
  strings:
    $key_1993 = { 4e e1 [2] 7c c3 [2] 7a f6 [2] 54 f6 [2] 6b ea }

  condition:
    any of them
}