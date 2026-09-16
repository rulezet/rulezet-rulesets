rule TTP_XOR_WriteProcessMemory_1a03 {
  strings:
    $key_1a03 = { 4d 71 [2] 7f 53 [2] 79 66 [2] 57 66 [2] 68 7a }

  condition:
    any of them
}