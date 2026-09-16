rule TTP_XOR_WriteProcessMemory_0f6c {
  strings:
    $key_0f6c = { 58 1e [2] 6a 3c [2] 6c 09 [2] 42 09 [2] 7d 15 }

  condition:
    any of them
}