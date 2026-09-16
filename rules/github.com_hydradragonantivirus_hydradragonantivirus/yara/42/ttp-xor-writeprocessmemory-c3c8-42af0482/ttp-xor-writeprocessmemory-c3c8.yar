rule TTP_XOR_WriteProcessMemory_c3c8 {
  strings:
    $key_c3c8 = { 94 ba [2] a6 98 [2] a0 ad [2] 8e ad [2] b1 b1 }

  condition:
    any of them
}