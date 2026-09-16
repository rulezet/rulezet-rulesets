rule TTP_XOR_WriteProcessMemory_6d65 {
  strings:
    $key_6d65 = { 3a 17 [2] 08 35 [2] 0e 00 [2] 20 00 [2] 1f 1c }

  condition:
    any of them
}