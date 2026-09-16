rule TTP_XOR_WriteProcessMemory_4bf2 {
  strings:
    $key_4bf2 = { 1c 80 [2] 2e a2 [2] 28 97 [2] 06 97 [2] 39 8b }

  condition:
    any of them
}