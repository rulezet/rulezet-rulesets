rule TTP_XOR_WriteProcessMemory_0673 {
  strings:
    $key_0673 = { 51 01 [2] 63 23 [2] 65 16 [2] 4b 16 [2] 74 0a }

  condition:
    any of them
}