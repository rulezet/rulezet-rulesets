rule TTP_XOR_WriteProcessMemory_46c8 {
  strings:
    $key_46c8 = { 11 ba [2] 23 98 [2] 25 ad [2] 0b ad [2] 34 b1 }

  condition:
    any of them
}