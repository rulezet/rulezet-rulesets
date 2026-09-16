rule TTP_XOR_WriteProcessMemory_1318 {
  strings:
    $key_1318 = { 44 6a [2] 76 48 [2] 70 7d [2] 5e 7d [2] 61 61 }

  condition:
    any of them
}