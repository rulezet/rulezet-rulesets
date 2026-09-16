rule TTP_XOR_WriteProcessMemory_e0c8 {
  strings:
    $key_e0c8 = { b7 ba [2] 85 98 [2] 83 ad [2] ad ad [2] 92 b1 }

  condition:
    any of them
}