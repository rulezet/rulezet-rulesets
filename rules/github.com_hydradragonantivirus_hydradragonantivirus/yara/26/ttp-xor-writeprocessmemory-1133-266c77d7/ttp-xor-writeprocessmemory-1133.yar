rule TTP_XOR_WriteProcessMemory_1133 {
  strings:
    $key_1133 = { 46 41 [2] 74 63 [2] 72 56 [2] 5c 56 [2] 63 4a }

  condition:
    any of them
}