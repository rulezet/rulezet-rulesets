rule TTP_XOR_WriteProcessMemory_51e4 {
  strings:
    $key_51e4 = { 06 96 [2] 34 b4 [2] 32 81 [2] 1c 81 [2] 23 9d }

  condition:
    any of them
}