rule TTP_XOR_WriteProcessMemory_73c8 {
  strings:
    $key_73c8 = { 24 ba [2] 16 98 [2] 10 ad [2] 3e ad [2] 01 b1 }

  condition:
    any of them
}