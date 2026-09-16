rule TTP_XOR_WriteProcessMemory_5a65 {
  strings:
    $key_5a65 = { 0d 17 [2] 3f 35 [2] 39 00 [2] 17 00 [2] 28 1c }

  condition:
    any of them
}