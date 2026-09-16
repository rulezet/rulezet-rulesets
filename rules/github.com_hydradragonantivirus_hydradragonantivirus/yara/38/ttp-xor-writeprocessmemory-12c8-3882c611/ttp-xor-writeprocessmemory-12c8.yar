rule TTP_XOR_WriteProcessMemory_12c8 {
  strings:
    $key_12c8 = { 45 ba [2] 77 98 [2] 71 ad [2] 5f ad [2] 60 b1 }

  condition:
    any of them
}