rule TTP_XOR_WriteProcessMemory_4e13 {
  strings:
    $key_4e13 = { 19 61 [2] 2b 43 [2] 2d 76 [2] 03 76 [2] 3c 6a }

  condition:
    any of them
}