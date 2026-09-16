rule TTP_XOR_WriteProcessMemory_0400 {
  strings:
    $key_0400 = { 53 72 [2] 61 50 [2] 67 65 [2] 49 65 [2] 76 79 }

  condition:
    any of them
}