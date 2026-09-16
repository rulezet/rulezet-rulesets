rule TTP_XOR_WriteProcessMemory_5bf2 {
  strings:
    $key_5bf2 = { 0c 80 [2] 3e a2 [2] 38 97 [2] 16 97 [2] 29 8b }

  condition:
    any of them
}