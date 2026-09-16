rule TTP_XOR_WriteProcessMemory_0745 {
  strings:
    $key_0745 = { 50 37 [2] 62 15 [2] 64 20 [2] 4a 20 [2] 75 3c }

  condition:
    any of them
}