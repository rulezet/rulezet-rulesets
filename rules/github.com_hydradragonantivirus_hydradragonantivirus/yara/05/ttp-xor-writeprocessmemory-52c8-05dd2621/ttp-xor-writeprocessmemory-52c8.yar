rule TTP_XOR_WriteProcessMemory_52c8 {
  strings:
    $key_52c8 = { 05 ba [2] 37 98 [2] 31 ad [2] 1f ad [2] 20 b1 }

  condition:
    any of them
}