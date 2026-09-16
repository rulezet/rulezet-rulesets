rule TTP_XOR_WriteProcessMemory_c1c8 {
  strings:
    $key_c1c8 = { 96 ba [2] a4 98 [2] a2 ad [2] 8c ad [2] b3 b1 }

  condition:
    any of them
}