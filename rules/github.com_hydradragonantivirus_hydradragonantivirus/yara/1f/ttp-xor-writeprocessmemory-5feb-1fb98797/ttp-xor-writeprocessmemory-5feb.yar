rule TTP_XOR_WriteProcessMemory_5feb {
  strings:
    $key_5feb = { 08 99 [2] 3a bb [2] 3c 8e [2] 12 8e [2] 2d 92 }

  condition:
    any of them
}