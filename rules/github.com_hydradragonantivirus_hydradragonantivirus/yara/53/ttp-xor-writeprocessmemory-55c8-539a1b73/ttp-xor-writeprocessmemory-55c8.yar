rule TTP_XOR_WriteProcessMemory_55c8 {
  strings:
    $key_55c8 = { 02 ba [2] 30 98 [2] 36 ad [2] 18 ad [2] 27 b1 }

  condition:
    any of them
}