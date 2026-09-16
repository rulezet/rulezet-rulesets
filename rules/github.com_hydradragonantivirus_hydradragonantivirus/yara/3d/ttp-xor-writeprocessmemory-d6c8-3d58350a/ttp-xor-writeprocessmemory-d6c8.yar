rule TTP_XOR_WriteProcessMemory_d6c8 {
  strings:
    $key_d6c8 = { 81 ba [2] b3 98 [2] b5 ad [2] 9b ad [2] a4 b1 }

  condition:
    any of them
}