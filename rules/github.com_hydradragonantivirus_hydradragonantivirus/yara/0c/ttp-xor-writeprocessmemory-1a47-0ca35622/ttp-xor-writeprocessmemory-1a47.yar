rule TTP_XOR_WriteProcessMemory_1a47 {
  strings:
    $key_1a47 = { 4d 35 [2] 7f 17 [2] 79 22 [2] 57 22 [2] 68 3e }

  condition:
    any of them
}