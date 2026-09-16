rule TTP_XOR_WriteProcessMemory_6832 {
  strings:
    $key_6832 = { 3f 40 [2] 0d 62 [2] 0b 57 [2] 25 57 [2] 1a 4b }

  condition:
    any of them
}