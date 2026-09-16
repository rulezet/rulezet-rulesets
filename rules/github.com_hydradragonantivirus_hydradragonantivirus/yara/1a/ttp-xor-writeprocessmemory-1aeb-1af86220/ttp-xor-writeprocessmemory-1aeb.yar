rule TTP_XOR_WriteProcessMemory_1aeb {
  strings:
    $key_1aeb = { 4d 99 [2] 7f bb [2] 79 8e [2] 57 8e [2] 68 92 }

  condition:
    any of them
}