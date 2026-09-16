rule TTP_XOR_WriteProcessMemory_5650 {
  strings:
    $key_5650 = { 01 22 [2] 33 00 [2] 35 35 [2] 1b 35 [2] 24 29 }

  condition:
    any of them
}