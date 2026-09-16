rule TTP_XOR_WriteProcessMemory_1104 {
  strings:
    $key_1104 = { 46 76 [2] 74 54 [2] 72 61 [2] 5c 61 [2] 63 7d }

  condition:
    any of them
}