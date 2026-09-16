rule TTP_XOR_WriteProcessMemory_7f53 {
  strings:
    $key_7f53 = { 28 21 [2] 1a 03 [2] 1c 36 [2] 32 36 [2] 0d 2a }

  condition:
    any of them
}