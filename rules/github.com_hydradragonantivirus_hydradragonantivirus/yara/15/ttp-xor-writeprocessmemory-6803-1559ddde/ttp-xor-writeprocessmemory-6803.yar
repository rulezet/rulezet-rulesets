rule TTP_XOR_WriteProcessMemory_6803 {
  strings:
    $key_6803 = { 3f 71 [2] 0d 53 [2] 0b 66 [2] 25 66 [2] 1a 7a }

  condition:
    any of them
}