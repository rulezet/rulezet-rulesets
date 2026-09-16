rule TTP_XOR_WriteProcessMemory_6fc8 {
  strings:
    $key_6fc8 = { 38 ba [2] 0a 98 [2] 0c ad [2] 22 ad [2] 1d b1 }

  condition:
    any of them
}