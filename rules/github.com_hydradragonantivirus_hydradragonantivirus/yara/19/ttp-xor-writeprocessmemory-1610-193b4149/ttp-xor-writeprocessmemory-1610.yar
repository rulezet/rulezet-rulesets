rule TTP_XOR_WriteProcessMemory_1610 {
  strings:
    $key_1610 = { 41 62 [2] 73 40 [2] 75 75 [2] 5b 75 [2] 64 69 }

  condition:
    any of them
}