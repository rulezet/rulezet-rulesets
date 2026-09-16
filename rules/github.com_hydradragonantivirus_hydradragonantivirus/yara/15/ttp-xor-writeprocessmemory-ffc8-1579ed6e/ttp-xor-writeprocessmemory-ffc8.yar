rule TTP_XOR_WriteProcessMemory_ffc8 {
  strings:
    $key_ffc8 = { a8 ba [2] 9a 98 [2] 9c ad [2] b2 ad [2] 8d b1 }

  condition:
    any of them
}