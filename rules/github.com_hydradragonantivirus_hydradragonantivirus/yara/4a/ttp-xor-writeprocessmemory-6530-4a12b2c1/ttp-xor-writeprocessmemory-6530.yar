rule TTP_XOR_WriteProcessMemory_6530 {
  strings:
    $key_6530 = { 32 42 [2] 00 60 [2] 06 55 [2] 28 55 [2] 17 49 }

  condition:
    any of them
}