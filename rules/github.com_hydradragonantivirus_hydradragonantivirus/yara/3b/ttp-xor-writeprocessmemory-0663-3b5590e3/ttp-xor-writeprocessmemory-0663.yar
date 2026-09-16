rule TTP_XOR_WriteProcessMemory_0663 {
  strings:
    $key_0663 = { 51 11 [2] 63 33 [2] 65 06 [2] 4b 06 [2] 74 1a }

  condition:
    any of them
}