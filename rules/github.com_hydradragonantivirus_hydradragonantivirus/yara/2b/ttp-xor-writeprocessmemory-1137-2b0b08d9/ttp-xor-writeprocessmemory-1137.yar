rule TTP_XOR_WriteProcessMemory_1137 {
  strings:
    $key_1137 = { 46 45 [2] 74 67 [2] 72 52 [2] 5c 52 [2] 63 4e }

  condition:
    any of them
}