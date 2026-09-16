rule TTP_XOR_WriteProcessMemory_02c8 {
  strings:
    $key_02c8 = { 55 ba [2] 67 98 [2] 61 ad [2] 4f ad [2] 70 b1 }

  condition:
    any of them
}