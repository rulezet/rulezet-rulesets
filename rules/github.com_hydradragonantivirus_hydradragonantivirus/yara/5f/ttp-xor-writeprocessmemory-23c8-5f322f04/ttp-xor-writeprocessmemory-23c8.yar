rule TTP_XOR_WriteProcessMemory_23c8 {
  strings:
    $key_23c8 = { 74 ba [2] 46 98 [2] 40 ad [2] 6e ad [2] 51 b1 }

  condition:
    any of them
}