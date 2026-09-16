rule TTP_XOR_WriteProcessMemory_24f3 {
  strings:
    $key_24f3 = { 73 81 [2] 41 a3 [2] 47 96 [2] 69 96 [2] 56 8a }

  condition:
    any of them
}