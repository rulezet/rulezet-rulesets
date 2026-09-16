rule TTP_XOR_WriteProcessMemory_6045 {
  strings:
    $key_6045 = { 37 37 [2] 05 15 [2] 03 20 [2] 2d 20 [2] 12 3c }

  condition:
    any of them
}