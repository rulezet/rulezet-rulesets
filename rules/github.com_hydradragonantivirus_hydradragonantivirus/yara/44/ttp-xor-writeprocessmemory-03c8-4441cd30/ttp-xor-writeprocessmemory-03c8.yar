rule TTP_XOR_WriteProcessMemory_03c8 {
  strings:
    $key_03c8 = { 54 ba [2] 66 98 [2] 60 ad [2] 4e ad [2] 71 b1 }

  condition:
    any of them
}