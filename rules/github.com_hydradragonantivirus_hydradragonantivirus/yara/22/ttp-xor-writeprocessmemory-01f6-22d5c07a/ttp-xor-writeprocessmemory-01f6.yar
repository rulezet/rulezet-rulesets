rule TTP_XOR_WriteProcessMemory_01f6 {
  strings:
    $key_01f6 = { 56 84 [2] 64 a6 [2] 62 93 [2] 4c 93 [2] 73 8f }

  condition:
    any of them
}