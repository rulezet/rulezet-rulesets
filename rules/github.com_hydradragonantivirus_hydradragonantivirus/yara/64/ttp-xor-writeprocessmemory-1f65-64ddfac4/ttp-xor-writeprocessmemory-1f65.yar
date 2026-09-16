rule TTP_XOR_WriteProcessMemory_1f65 {
  strings:
    $key_1f65 = { 48 17 [2] 7a 35 [2] 7c 00 [2] 52 00 [2] 6d 1c }

  condition:
    any of them
}