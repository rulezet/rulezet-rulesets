rule TTP_XOR_WriteProcessMemory_2aeb {
  strings:
    $key_2aeb = { 7d 99 [2] 4f bb [2] 49 8e [2] 67 8e [2] 58 92 }

  condition:
    any of them
}