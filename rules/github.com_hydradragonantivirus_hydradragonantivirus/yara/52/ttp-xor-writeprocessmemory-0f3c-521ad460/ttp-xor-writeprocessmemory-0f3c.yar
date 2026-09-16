rule TTP_XOR_WriteProcessMemory_0f3c {
  strings:
    $key_0f3c = { 58 4e [2] 6a 6c [2] 6c 59 [2] 42 59 [2] 7d 45 }

  condition:
    any of them
}