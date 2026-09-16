rule TTP_XOR_WriteProcessMemory_4e23 {
  strings:
    $key_4e23 = { 19 51 [2] 2b 73 [2] 2d 46 [2] 03 46 [2] 3c 5a }

  condition:
    any of them
}