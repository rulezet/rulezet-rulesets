rule TTP_XOR_WriteProcessMemory_6e13 {
  strings:
    $key_6e13 = { 39 61 [2] 0b 43 [2] 0d 76 [2] 23 76 [2] 1c 6a }

  condition:
    any of them
}