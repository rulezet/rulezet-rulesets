rule TTP_XOR_WriteProcessMemory_6823 {
  strings:
    $key_6823 = { 3f 51 [2] 0d 73 [2] 0b 46 [2] 25 46 [2] 1a 5a }

  condition:
    any of them
}