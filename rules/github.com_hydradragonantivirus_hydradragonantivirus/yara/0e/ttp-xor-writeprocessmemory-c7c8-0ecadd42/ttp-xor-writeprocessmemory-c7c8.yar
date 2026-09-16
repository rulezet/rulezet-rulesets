rule TTP_XOR_WriteProcessMemory_c7c8 {
  strings:
    $key_c7c8 = { 90 ba [2] a2 98 [2] a4 ad [2] 8a ad [2] b5 b1 }

  condition:
    any of them
}