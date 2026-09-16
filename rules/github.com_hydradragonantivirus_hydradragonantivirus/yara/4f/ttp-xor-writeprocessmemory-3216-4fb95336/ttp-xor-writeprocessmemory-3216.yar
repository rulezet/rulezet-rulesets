rule TTP_XOR_WriteProcessMemory_3216 {
  strings:
    $key_3216 = { 65 64 [2] 57 46 [2] 51 73 [2] 7f 73 [2] 40 6f }

  condition:
    any of them
}