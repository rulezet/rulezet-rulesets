rule TTP_XOR_WriteProcessMemory_1378 {
  strings:
    $key_1378 = { 44 0a [2] 76 28 [2] 70 1d [2] 5e 1d [2] 61 01 }

  condition:
    any of them
}