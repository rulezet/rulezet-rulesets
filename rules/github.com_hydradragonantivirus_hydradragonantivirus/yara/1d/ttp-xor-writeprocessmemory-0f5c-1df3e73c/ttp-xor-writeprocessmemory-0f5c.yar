rule TTP_XOR_WriteProcessMemory_0f5c {
  strings:
    $key_0f5c = { 58 2e [2] 6a 0c [2] 6c 39 [2] 42 39 [2] 7d 25 }

  condition:
    any of them
}