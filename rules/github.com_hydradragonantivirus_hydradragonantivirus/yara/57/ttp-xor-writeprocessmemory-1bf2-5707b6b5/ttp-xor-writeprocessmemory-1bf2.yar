rule TTP_XOR_WriteProcessMemory_1bf2 {
  strings:
    $key_1bf2 = { 4c 80 [2] 7e a2 [2] 78 97 [2] 56 97 [2] 69 8b }

  condition:
    any of them
}