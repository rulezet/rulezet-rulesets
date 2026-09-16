rule TTP_XOR_WriteProcessMemory_0441 {
  strings:
    $key_0441 = { 53 33 [2] 61 11 [2] 67 24 [2] 49 24 [2] 76 38 }

  condition:
    any of them
}