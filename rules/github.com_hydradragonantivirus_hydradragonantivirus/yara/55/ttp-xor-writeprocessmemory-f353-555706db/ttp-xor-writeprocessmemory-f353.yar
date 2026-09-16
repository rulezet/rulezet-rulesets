rule TTP_XOR_WriteProcessMemory_f353 {
  strings:
    $key_f353 = { a4 21 [2] 96 03 [2] 90 36 [2] be 36 [2] 81 2a }

  condition:
    any of them
}