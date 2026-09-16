rule TTP_XOR_WriteProcessMemory_71c8 {
  strings:
    $key_71c8 = { 26 ba [2] 14 98 [2] 12 ad [2] 3c ad [2] 03 b1 }

  condition:
    any of them
}