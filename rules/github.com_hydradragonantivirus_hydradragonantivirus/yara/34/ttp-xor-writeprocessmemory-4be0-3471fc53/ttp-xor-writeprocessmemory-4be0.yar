rule TTP_XOR_WriteProcessMemory_4be0 {
  strings:
    $key_4be0 = { 1c 92 [2] 2e b0 [2] 28 85 [2] 06 85 [2] 39 99 }

  condition:
    any of them
}