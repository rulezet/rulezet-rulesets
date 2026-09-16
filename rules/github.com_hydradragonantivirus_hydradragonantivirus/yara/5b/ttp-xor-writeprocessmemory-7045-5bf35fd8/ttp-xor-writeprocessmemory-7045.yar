rule TTP_XOR_WriteProcessMemory_7045 {
  strings:
    $key_7045 = { 27 37 [2] 15 15 [2] 13 20 [2] 3d 20 [2] 02 3c }

  condition:
    any of them
}