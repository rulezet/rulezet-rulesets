rule TTP_XOR_WriteProcessMemory_ecce {
  strings:
    $key_ecce = { bb bc [2] 89 9e [2] 8f ab [2] a1 ab [2] 9e b7 }

  condition:
    any of them
}