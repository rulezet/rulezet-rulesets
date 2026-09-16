rule TTP_XOR_WriteProcessMemory_4bce {
  strings:
    $key_4bce = { 1c bc [2] 2e 9e [2] 28 ab [2] 06 ab [2] 39 b7 }

  condition:
    any of them
}