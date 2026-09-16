rule TTP_XOR_WriteProcessMemory_15c8 {
  strings:
    $key_15c8 = { 42 ba [2] 70 98 [2] 76 ad [2] 58 ad [2] 67 b1 }

  condition:
    any of them
}