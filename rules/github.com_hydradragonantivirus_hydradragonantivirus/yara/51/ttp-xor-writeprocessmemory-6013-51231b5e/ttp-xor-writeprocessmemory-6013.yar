rule TTP_XOR_WriteProcessMemory_6013 {
  strings:
    $key_6013 = { 37 61 [2] 05 43 [2] 03 76 [2] 2d 76 [2] 12 6a }

  condition:
    any of them
}