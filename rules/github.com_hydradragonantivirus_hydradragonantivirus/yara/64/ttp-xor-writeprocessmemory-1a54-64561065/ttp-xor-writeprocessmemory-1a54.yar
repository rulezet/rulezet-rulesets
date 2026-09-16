rule TTP_XOR_WriteProcessMemory_1a54 {
  strings:
    $key_1a54 = { 4d 26 [2] 7f 04 [2] 79 31 [2] 57 31 [2] 68 2d }

  condition:
    any of them
}