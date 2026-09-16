rule TTP_XOR_WriteProcessMemory_4b79 {
  strings:
    $key_4b79 = { 1c 0b [2] 2e 29 [2] 28 1c [2] 06 1c [2] 39 00 }

  condition:
    any of them
}