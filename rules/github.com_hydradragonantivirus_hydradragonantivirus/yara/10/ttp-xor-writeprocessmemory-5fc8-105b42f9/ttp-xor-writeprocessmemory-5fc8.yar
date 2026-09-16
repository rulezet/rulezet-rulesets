rule TTP_XOR_WriteProcessMemory_5fc8 {
  strings:
    $key_5fc8 = { 08 ba [2] 3a 98 [2] 3c ad [2] 12 ad [2] 2d b1 }

  condition:
    any of them
}