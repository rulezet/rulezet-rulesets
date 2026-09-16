rule TTP_XOR_WriteProcessMemory_6023 {
  strings:
    $key_6023 = { 37 51 [2] 05 73 [2] 03 46 [2] 2d 46 [2] 12 5a }

  condition:
    any of them
}