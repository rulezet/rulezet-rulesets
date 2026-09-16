rule TTP_XOR_WriteProcessMemory_4b51 {
  strings:
    $key_4b51 = { 1c 23 [2] 2e 01 [2] 28 34 [2] 06 34 [2] 39 28 }

  condition:
    any of them
}