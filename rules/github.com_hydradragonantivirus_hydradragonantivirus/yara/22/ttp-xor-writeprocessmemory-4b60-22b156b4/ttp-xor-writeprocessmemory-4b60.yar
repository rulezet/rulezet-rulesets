rule TTP_XOR_WriteProcessMemory_4b60 {
  strings:
    $key_4b60 = { 1c 12 [2] 2e 30 [2] 28 05 [2] 06 05 [2] 39 19 }

  condition:
    any of them
}