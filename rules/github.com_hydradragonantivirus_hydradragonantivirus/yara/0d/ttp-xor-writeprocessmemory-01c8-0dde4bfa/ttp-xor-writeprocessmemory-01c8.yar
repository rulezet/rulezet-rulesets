rule TTP_XOR_WriteProcessMemory_01c8 {
  strings:
    $key_01c8 = { 56 ba [2] 64 98 [2] 62 ad [2] 4c ad [2] 73 b1 }

  condition:
    any of them
}