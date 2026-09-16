rule TTP_XOR_WriteProcessMemory_2bf6 {
  strings:
    $key_2bf6 = { 7c 84 [2] 4e a6 [2] 48 93 [2] 66 93 [2] 59 8f }

  condition:
    any of them
}