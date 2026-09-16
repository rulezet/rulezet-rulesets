rule TTP_XOR_WriteProcessMemory_24c8 {
  strings:
    $key_24c8 = { 73 ba [2] 41 98 [2] 47 ad [2] 69 ad [2] 56 b1 }

  condition:
    any of them
}