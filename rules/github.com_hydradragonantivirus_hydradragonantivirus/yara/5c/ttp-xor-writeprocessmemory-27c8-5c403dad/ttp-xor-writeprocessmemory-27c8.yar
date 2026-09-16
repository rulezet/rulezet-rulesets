rule TTP_XOR_WriteProcessMemory_27c8 {
  strings:
    $key_27c8 = { 70 ba [2] 42 98 [2] 44 ad [2] 6a ad [2] 55 b1 }

  condition:
    any of them
}