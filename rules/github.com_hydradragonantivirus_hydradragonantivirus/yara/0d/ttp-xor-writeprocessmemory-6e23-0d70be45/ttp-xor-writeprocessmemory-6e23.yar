rule TTP_XOR_WriteProcessMemory_6e23 {
  strings:
    $key_6e23 = { 39 51 [2] 0b 73 [2] 0d 46 [2] 23 46 [2] 1c 5a }

  condition:
    any of them
}