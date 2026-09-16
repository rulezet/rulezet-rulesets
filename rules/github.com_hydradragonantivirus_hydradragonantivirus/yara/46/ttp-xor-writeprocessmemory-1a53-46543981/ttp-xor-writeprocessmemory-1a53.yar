rule TTP_XOR_WriteProcessMemory_1a53 {
  strings:
    $key_1a53 = { 4d 21 [2] 7f 03 [2] 79 36 [2] 57 36 [2] 68 2a }

  condition:
    any of them
}