rule TTP_XOR_WriteProcessMemory_6007 {
  strings:
    $key_6007 = { 37 75 [2] 05 57 [2] 03 62 [2] 2d 62 [2] 12 7e }

  condition:
    any of them
}