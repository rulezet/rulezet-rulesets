rule TTP_XOR_WriteProcessMemory_1f53 {
  strings:
    $key_1f53 = { 48 21 [2] 7a 03 [2] 7c 36 [2] 52 36 [2] 6d 2a }

  condition:
    any of them
}