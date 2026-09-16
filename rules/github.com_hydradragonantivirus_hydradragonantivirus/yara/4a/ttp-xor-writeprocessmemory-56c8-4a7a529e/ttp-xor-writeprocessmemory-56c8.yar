rule TTP_XOR_WriteProcessMemory_56c8 {
  strings:
    $key_56c8 = { 01 ba [2] 33 98 [2] 35 ad [2] 1b ad [2] 24 b1 }

  condition:
    any of them
}