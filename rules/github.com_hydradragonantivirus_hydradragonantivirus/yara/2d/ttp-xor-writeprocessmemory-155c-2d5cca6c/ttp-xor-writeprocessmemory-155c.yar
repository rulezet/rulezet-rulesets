rule TTP_XOR_WriteProcessMemory_155c {
  strings:
    $key_155c = { 42 2e [2] 70 0c [2] 76 39 [2] 58 39 [2] 67 25 }

  condition:
    any of them
}