rule TTP_XOR_WriteProcessMemory_5611 {
  strings:
    $key_5611 = { 01 63 [2] 33 41 [2] 35 74 [2] 1b 74 [2] 24 68 }

  condition:
    any of them
}