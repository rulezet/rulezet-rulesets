rule TTP_XOR_WriteProcessMemory_1cce {
  strings:
    $key_1cce = { 4b bc [2] 79 9e [2] 7f ab [2] 51 ab [2] 6e b7 }

  condition:
    any of them
}