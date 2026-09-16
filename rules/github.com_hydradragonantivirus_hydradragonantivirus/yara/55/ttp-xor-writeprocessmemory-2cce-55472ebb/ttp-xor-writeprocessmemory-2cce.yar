rule TTP_XOR_WriteProcessMemory_2cce {
  strings:
    $key_2cce = { 7b bc [2] 49 9e [2] 4f ab [2] 61 ab [2] 5e b7 }

  condition:
    any of them
}