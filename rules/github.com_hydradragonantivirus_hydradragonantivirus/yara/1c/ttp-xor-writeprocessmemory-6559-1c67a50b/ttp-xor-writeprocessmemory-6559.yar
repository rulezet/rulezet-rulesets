rule TTP_XOR_WriteProcessMemory_6559 {
  strings:
    $key_6559 = { 32 2b [2] 00 09 [2] 06 3c [2] 28 3c [2] 17 20 }

  condition:
    any of them
}