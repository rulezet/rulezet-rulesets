rule TTP_XOR_WriteProcessMemory_fbc8 {
  strings:
    $key_fbc8 = { ac ba [2] 9e 98 [2] 98 ad [2] b6 ad [2] 89 b1 }

  condition:
    any of them
}