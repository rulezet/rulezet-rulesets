rule TTP_XOR_WriteProcessMemory_1177 {
  strings:
    $key_1177 = { 46 05 [2] 74 27 [2] 72 12 [2] 5c 12 [2] 63 0e }

  condition:
    any of them
}