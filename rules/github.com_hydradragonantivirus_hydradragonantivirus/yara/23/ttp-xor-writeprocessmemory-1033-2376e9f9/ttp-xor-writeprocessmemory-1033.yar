rule TTP_XOR_WriteProcessMemory_1033 {
  strings:
    $key_1033 = { 47 41 [2] 75 63 [2] 73 56 [2] 5d 56 [2] 62 4a }

  condition:
    any of them
}