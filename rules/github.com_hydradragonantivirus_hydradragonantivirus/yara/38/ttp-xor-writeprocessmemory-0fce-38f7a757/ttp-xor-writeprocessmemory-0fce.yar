rule TTP_XOR_WriteProcessMemory_0fce {
  strings:
    $key_0fce = { 58 bc [2] 6a 9e [2] 6c ab [2] 42 ab [2] 7d b7 }

  condition:
    any of them
}