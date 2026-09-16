rule TTP_XOR_WriteProcessMemory_3cce {
  strings:
    $key_3cce = { 6b bc [2] 59 9e [2] 5f ab [2] 71 ab [2] 4e b7 }

  condition:
    any of them
}