rule TTP_XOR_WriteProcessMemory_7f51 {
  strings:
    $key_7f51 = { 28 23 [2] 1a 01 [2] 1c 34 [2] 32 34 [2] 0d 28 }

  condition:
    any of them
}