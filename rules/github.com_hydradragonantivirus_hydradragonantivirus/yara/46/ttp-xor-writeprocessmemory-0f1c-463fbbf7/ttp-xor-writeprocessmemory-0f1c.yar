rule TTP_XOR_WriteProcessMemory_0f1c {
  strings:
    $key_0f1c = { 58 6e [2] 6a 4c [2] 6c 79 [2] 42 79 [2] 7d 65 }

  condition:
    any of them
}