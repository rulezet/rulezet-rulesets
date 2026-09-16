rule TTP_XOR_WriteProcessMemory_21c8 {
  strings:
    $key_21c8 = { 76 ba [2] 44 98 [2] 42 ad [2] 6c ad [2] 53 b1 }

  condition:
    any of them
}