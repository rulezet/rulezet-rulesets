rule TTP_XOR_WriteProcessMemory_6813 {
  strings:
    $key_6813 = { 3f 61 [2] 0d 43 [2] 0b 76 [2] 25 76 [2] 1a 6a }

  condition:
    any of them
}