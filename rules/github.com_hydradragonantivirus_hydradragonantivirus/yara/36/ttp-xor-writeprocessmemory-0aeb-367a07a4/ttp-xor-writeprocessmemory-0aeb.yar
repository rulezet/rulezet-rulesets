rule TTP_XOR_WriteProcessMemory_0aeb {
  strings:
    $key_0aeb = { 5d 99 [2] 6f bb [2] 69 8e [2] 47 8e [2] 78 92 }

  condition:
    any of them
}