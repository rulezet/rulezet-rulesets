rule TTP_XOR_WriteProcessMemory_e5c8 {
  strings:
    $key_e5c8 = { b2 ba [2] 80 98 [2] 86 ad [2] a8 ad [2] 97 b1 }

  condition:
    any of them
}