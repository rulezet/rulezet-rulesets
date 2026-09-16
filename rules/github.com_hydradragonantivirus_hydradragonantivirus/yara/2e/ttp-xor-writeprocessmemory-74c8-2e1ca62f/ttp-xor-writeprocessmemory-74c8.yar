rule TTP_XOR_WriteProcessMemory_74c8 {
  strings:
    $key_74c8 = { 23 ba [2] 11 98 [2] 17 ad [2] 39 ad [2] 06 b1 }

  condition:
    any of them
}