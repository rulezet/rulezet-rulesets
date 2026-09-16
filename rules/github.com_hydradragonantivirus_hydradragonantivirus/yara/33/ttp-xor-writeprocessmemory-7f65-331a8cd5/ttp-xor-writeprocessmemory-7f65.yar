rule TTP_XOR_WriteProcessMemory_7f65 {
  strings:
    $key_7f65 = { 28 17 [2] 1a 35 [2] 1c 00 [2] 32 00 [2] 0d 1c }

  condition:
    any of them
}