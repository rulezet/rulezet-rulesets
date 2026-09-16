rule TTP_XOR_WriteProcessMemory_6065 {
  strings:
    $key_6065 = { 37 17 [2] 05 35 [2] 03 00 [2] 2d 00 [2] 12 1c }

  condition:
    any of them
}