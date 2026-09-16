rule TTP_XOR_WriteProcessMemory_32f6 {
  strings:
    $key_32f6 = { 65 84 [2] 57 a6 [2] 51 93 [2] 7f 93 [2] 40 8f }

  condition:
    any of them
}