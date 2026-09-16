rule TTP_XOR_WriteProcessMemory_f3c8 {
  strings:
    $key_f3c8 = { a4 ba [2] 96 98 [2] 90 ad [2] be ad [2] 81 b1 }

  condition:
    any of them
}