rule TTP_XOR_WriteProcessMemory_17c8 {
  strings:
    $key_17c8 = { 40 ba [2] 72 98 [2] 74 ad [2] 5a ad [2] 65 b1 }

  condition:
    any of them
}