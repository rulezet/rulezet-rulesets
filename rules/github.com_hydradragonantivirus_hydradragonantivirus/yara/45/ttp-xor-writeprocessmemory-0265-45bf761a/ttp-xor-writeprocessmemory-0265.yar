rule TTP_XOR_WriteProcessMemory_0265 {
  strings:
    $key_0265 = { 55 17 [2] 67 35 [2] 61 00 [2] 4f 00 [2] 70 1c }

  condition:
    any of them
}