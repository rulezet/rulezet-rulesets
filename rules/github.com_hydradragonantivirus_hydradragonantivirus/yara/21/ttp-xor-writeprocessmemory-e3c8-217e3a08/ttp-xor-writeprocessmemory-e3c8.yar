rule TTP_XOR_WriteProcessMemory_e3c8 {
  strings:
    $key_e3c8 = { b4 ba [2] 86 98 [2] 80 ad [2] ae ad [2] 91 b1 }

  condition:
    any of them
}