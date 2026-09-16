rule TTP_XOR_WriteProcessMemory_1611 {
  strings:
    $key_1611 = { 41 63 [2] 73 41 [2] 75 74 [2] 5b 74 [2] 64 68 }

  condition:
    any of them
}