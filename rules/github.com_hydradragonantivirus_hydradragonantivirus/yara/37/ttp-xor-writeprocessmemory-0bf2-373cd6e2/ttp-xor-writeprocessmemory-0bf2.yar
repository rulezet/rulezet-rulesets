rule TTP_XOR_WriteProcessMemory_0bf2 {
  strings:
    $key_0bf2 = { 5c 80 [2] 6e a2 [2] 68 97 [2] 46 97 [2] 79 8b }

  condition:
    any of them
}