rule TTP_XOR_WriteProcessMemory_6879 {
  strings:
    $key_6879 = { 3f 0b [2] 0d 29 [2] 0b 1c [2] 25 1c [2] 1a 00 }

  condition:
    any of them
}