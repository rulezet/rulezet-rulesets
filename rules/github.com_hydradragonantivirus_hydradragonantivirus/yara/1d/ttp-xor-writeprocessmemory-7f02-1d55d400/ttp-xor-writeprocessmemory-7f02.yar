rule TTP_XOR_WriteProcessMemory_7f02 {
  strings:
    $key_7f02 = { 28 70 [2] 1a 52 [2] 1c 67 [2] 32 67 [2] 0d 7b }

  condition:
    any of them
}