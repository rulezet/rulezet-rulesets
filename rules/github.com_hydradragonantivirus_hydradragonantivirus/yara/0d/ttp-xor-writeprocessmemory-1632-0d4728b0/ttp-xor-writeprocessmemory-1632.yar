rule TTP_XOR_WriteProcessMemory_1632 {
  strings:
    $key_1632 = { 41 40 [2] 73 62 [2] 75 57 [2] 5b 57 [2] 64 4b }

  condition:
    any of them
}