rule TTP_XOR_WriteProcessMemory_14c8 {
  strings:
    $key_14c8 = { 43 ba [2] 71 98 [2] 77 ad [2] 59 ad [2] 66 b1 }

  condition:
    any of them
}