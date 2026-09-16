rule TTP_XOR_WriteProcessMemory_0bce {
  strings:
    $key_0bce = { 5c bc [2] 6e 9e [2] 68 ab [2] 46 ab [2] 79 b7 }

  condition:
    any of them
}