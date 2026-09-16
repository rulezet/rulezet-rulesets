rule TTP_XOR_WriteProcessMemory_1a31 {
  strings:
    $key_1a31 = { 4d 43 [2] 7f 61 [2] 79 54 [2] 57 54 [2] 68 48 }

  condition:
    any of them
}