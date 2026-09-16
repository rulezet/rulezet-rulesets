rule TTP_XOR_WriteProcessMemory_07c8 {
  strings:
    $key_07c8 = { 50 ba [2] 62 98 [2] 64 ad [2] 4a ad [2] 75 b1 }

  condition:
    any of them
}