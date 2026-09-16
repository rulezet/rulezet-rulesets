rule TTP_XOR_WriteProcessMemory_26c8 {
  strings:
    $key_26c8 = { 71 ba [2] 43 98 [2] 45 ad [2] 6b ad [2] 54 b1 }

  condition:
    any of them
}