rule TTP_XOR_WriteProcessMemory_0753 {
  strings:
    $key_0753 = { 50 21 [2] 62 03 [2] 64 36 [2] 4a 36 [2] 75 2a }

  condition:
    any of them
}