rule TTP_XOR_WriteProcessMemory_6870 {
  strings:
    $key_6870 = { 3f 02 [2] 0d 20 [2] 0b 15 [2] 25 15 [2] 1a 09 }

  condition:
    any of them
}